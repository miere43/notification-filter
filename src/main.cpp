#include <xbyak/xbyak.h>
#include <SKSE/Trampoline.h>
#include "SimpleIni.h"

namespace
{
	constexpr auto PapyrusDebugNotificationID = REL::ID(55269);
	constexpr auto GetNotificationTextID = REL::ID(104285);

	struct TextPattern
	{
		std::string text;
	};

	struct RegularExpressionPattern
	{
		std::string originalString;
		std::regex regex;
	};

	using AnyPattern = std::variant<TextPattern, RegularExpressionPattern>;

	struct PatternLoad
	{
		AnyPattern value;
		int order;
	};

	struct Settings
	{
		bool enableLog = false;
		std::vector<AnyPattern> patterns;

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

		Settings::instance.enableLog = ini.GetBoolValue("General", "EnableLog", Settings::instance.enableLog);

		std::vector<PatternLoad> patterns;

		std::list<CSimpleIniA::Entry> entries;
		ini.GetAllValues("Filters", "Hide", entries);

		for (const auto& entry : entries) {
			patterns.push_back({ TextPattern{ std::string(entry.pItem) }, entry.nOrder });
		}

		entries.clear();
		ini.GetAllValues("Filters", "HideRegex", entries);

		for (const auto& entry : entries) {
			std::string originalString(entry.pItem);
			std::regex pattern;
			try {
				pattern = std::regex(originalString, std::regex_constants::ECMAScript);
			}
			catch (const std::regex_error& e) {
				logger::error("- Error parsing regular expression \"{}\": \"{}\"", originalString, e.what());
				continue;
			}

			patterns.push_back({ RegularExpressionPattern{ originalString, pattern }, entry.nOrder });
		}

		std::sort(patterns.begin(), patterns.end(), [](const PatternLoad& a, const PatternLoad& b) {
			return a.order > b.order;
		});

		Settings::instance.patterns.reserve(patterns.size());
		for (const auto& pattern : patterns) {
			Settings::instance.patterns.push_back(pattern.value);
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

	static bool ShouldSkipNotification(const char** textPtrRef)
	{
		const auto text = std::string_view(*textPtrRef);
		for (const auto& pattern : Settings::instance.patterns) {
			if (std::holds_alternative<TextPattern>(pattern)) {
				const auto& textPattern = std::get<TextPattern>(pattern);
				if (textPattern.text == text) {
					if (Settings::instance.enableLog) {
						logger::info("Hiding notification \"{}\" because it matches text pattern \"{}\"", text, textPattern.text);
					}
					return true;
				}
			} else {
				const auto& regexPattern = std::get<RegularExpressionPattern>(pattern);
				if (std::regex_match(text.data(), regexPattern.regex)) {
					if (Settings::instance.enableLog) {
						logger::info("Hiding notification \"{}\" because it matches regular expression pattern \"{}\"", text, regexPattern.originalString);
					}
					return true;
				}
			}
		}

		if (Settings::instance.enableLog) {
			logger::info("Showing notification \"{}\" because it doesn't match any known patterns", text);
		}

		return false;
	}

	struct DebugNotificationCode : Xbyak::CodeGenerator
	{
		DebugNotificationCode()
		{
			// Restore call that was overwritten by trampoline.
			mov(rax, REL::Relocation<uintptr_t>(GetNotificationTextID).get());
			call(rax);

			// Now RAX is pointer to notification text (null-terminated, char**).
			mov(rcx, rax); // copy for func argument

			push(rcx);
			push(rdx);
			push(r8);
			push(r9);
			push(r10);
			push(r11);

			sub(rsp, 0x20); // 16 byte alignment! Needed for FPU operations.
			mov(rax, (uintptr_t)std::addressof(ShouldSkipNotification));
			call(rax);
			add(rsp, 0x20);

			// TODO: do I need to save XMM?
			pop(r11);
			pop(r10);
			pop(r9);
			pop(r8);
			pop(rdx);
			pop(rcx);

			cmp(al, 0);
			je("ok");

			// If return value is 1, exit from function (don't show notification).
			mov(rax, REL::Relocation<uintptr_t>(PapyrusDebugNotificationID, 0xD0).get());
			jmp(rax);

			// Otherwise, jump back to normal control flow (show notification).
			L("ok");
			mov(rax, rcx);  // Return notification text.
			mov(rcx, REL::Relocation<uintptr_t>(PapyrusDebugNotificationID, 0x56).get());
			jmp(rcx);
		}
	};

	static void Install()
	{
		auto codeGen = new DebugNotificationCode();
		auto codePtr = codeGen->getCode();

		SKSE::AllocTrampoline(20);

		// Replace call to GetNotificationText with our code.
		SKSE::GetTrampoline().write_branch<5>(REL::Relocation<uintptr_t>(PapyrusDebugNotificationID, 0x51).get(), codePtr);
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
	logger::info("Using settings: EnableLog = {}, {} patterns loaded.", Settings::instance.enableLog, Settings::instance.patterns.size());
	if (Settings::instance.enableLog && Settings::instance.patterns.size()) {
		logger::info("Loaded patterns:");
		int index = 0;
		for (const auto& pattern : Settings::instance.patterns) {
			++index;
			if (std::holds_alternative<TextPattern>(pattern)) {
				const auto& text = std::get<TextPattern>(pattern);
				logger::info("{}. Text \"{}\"", index, text.text);
			} else {
				const auto& regex = std::get<RegularExpressionPattern>(pattern);
				logger::info("{}. Regular Expression \"{}\"", index, regex.originalString);
			}
		}
	}

	SKSE::Init(a_skse);

	if (Settings::instance.patterns.size() == 0) {
		logger::error("No patterns were registered, skipping patching.");
	} else {
		Install();
		logger::info("Installed patch.");
	}

	return true;
}
