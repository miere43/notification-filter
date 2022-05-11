#include <xbyak/xbyak.h>
#include <SKSE/Trampoline.h>
#include "SimpleIni.h"

namespace
{
	struct Settings
	{
		bool logNotifications = false;
		std::vector<std::string> hideTexts;

		static Settings instance;
	};
	Settings Settings::instance;

	void LoadSettings()
	{
		CSimpleIniA ini;
		ini.SetUnicode(true);
		ini.SetMultiKey(true);

		auto rc = ini.LoadFile(L"Data/SKSE/Plugins/NotificationFilter.ini");
		if (rc < 0) {
			logger::error("Failed to read INI settings from Data/SKSE/Plugins/NotificationFilter.ini, using default settings (error code was {})", rc);
			return;
		}

		Settings::instance.logNotifications = ini.GetBoolValue("General", "LogNotifications", Settings::instance.logNotifications);

		std::list<CSimpleIniA::Entry> hideEntries;
		ini.GetAllValues("Filters", "Hide", hideEntries);

		for (const auto& entry : hideEntries) {
			Settings::instance.hideTexts.push_back(std::string(entry.pItem));
		}
	}

	void InitializeLog()
	{
		auto path = logger::log_directory();
		if (!path) {
			util::report_and_fail("Failed to find standard logging directory"sv);
		}

		*path /= fmt::format("{}.log"sv, Plugin::NAME);
		auto sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(path->string(), true);

		const auto level = spdlog::level::info;

		auto log = std::make_shared<spdlog::logger>("global log"s, std::move(sink));
		log->set_level(level);
		log->flush_on(level);

		spdlog::set_default_logger(std::move(log));
		spdlog::set_pattern("%g(%#): [%^%l%$] %v"s);
	}

	static bool __fastcall ShouldSkipNotification(const char** textPtrRef)
	{
		auto textPtr = *textPtrRef;
		const auto text = std::string_view(textPtr);
		for (const auto& hideText : Settings::instance.hideTexts) {
			if (hideText == text) {
				//if (Settings::instance.logNotifications) {
					//logger::info("Hiding notification \"{}\" because it matches pattern \"{}\"", text, hideText);
				//}
				return true;
			}
		}

		//if (Settings::instance.logNotifications) {
			//logger::info("Showing notification \"{}\" because it doesn't match any known patterns", text);
		//}

		return false;
	}

	struct DebugNotificationCode : Xbyak::CodeGenerator
	{
		DebugNotificationCode()
		{
			// Restore call that was overwritten by trampoline.
			mov(rax, REL::Relocation<uintptr_t>(REL::Offset(0x1360EF0)).get());
			call(rax);

			// Now RAX is pointer to notification text (null-terminated, char**).
			mov(rcx, rax); // copy for func argument

			push(rcx);
			push(rdx);
			push(r8);
			push(r9);
			push(r10);
			push(r11);

			sub(rsp, 40);
			mov(rax, (uintptr_t)std::addressof(ShouldSkipNotification));
			call(rax);
			add(rsp, 40);

			// TODO: XMM?
			pop(r11);
			pop(r10);
			pop(r9);
			pop(r8);
			pop(rdx);
			pop(rcx);

			cmp(al, 0);
			je("ok");

			// If return value is 0, exit from function (don't show notification).
			mov(rax, REL::Relocation<uintptr_t>(REL::Offset(0x9923F0)).get());
			jmp(rax);

			// Otherwise, jump back to normal control flow (show notification).
			L("ok");
			mov(rax, rcx);  // Return notification text.
			mov(rcx, REL::Relocation<uintptr_t>(REL::Offset(0x992376)).get());
			jmp(rcx);
		}
	};

	static void Install()
	{
		REL::Relocation<uintptr_t> debugNotificationFuncContent(REL::Offset(0x992371));
		auto debugNotificationFuncStartPtr = debugNotificationFuncContent.get();

		auto bruh = new DebugNotificationCode();
		auto codePtr = bruh->getCode();

		SKSE::AllocTrampoline(2048);

		// Replace 5 bytes of this instruction with trampoline.
		// E8 7AEB9C00 | call <skyrimse.GetNotificationText>
		SKSE::GetTrampoline().write_branch<5>(debugNotificationFuncStartPtr, codePtr);
	}
}

extern "C" DLLEXPORT auto constinit SKSEPlugin_Version = []() {
	SKSE::PluginVersionData v;

	v.PluginVersion(Plugin::VERSION);
	v.PluginName(Plugin::NAME);
	v.AuthorName("miere");
	v.UsesAddressLibrary(true);
	v.CompatibleVersions({ SKSE::RUNTIME_LATEST });

	return v;
}();

extern "C" DLLEXPORT bool SKSEAPI SKSEPlugin_Load(const SKSE::LoadInterface* a_skse)
{
	InitializeLog();
	logger::info("{} v{}"sv, Plugin::NAME, Plugin::VERSION.string());
	
	LoadSettings();
	logger::info("Using settings: LogNotifications = {}, removal entries count = {}", Settings::instance.logNotifications, Settings::instance.hideTexts.size());

	SKSE::Init(a_skse);

	if (Settings::instance.hideTexts.size() == 0) {
		logger::error("No removal entries were registered, skipping patching.");
	} else {
		Install();
		logger::info("Installed patch.");
	}

	return true;
}
