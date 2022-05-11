#include <xbyak/xbyak.h>
#include <SKSE/Trampoline.h>

namespace
{
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

	extern "C" static bool ShouldSkipNotification(const char* text)
	{
		return false;
	}

	struct DebugNotificationCode : Xbyak::CodeGenerator
	{
		DebugNotificationCode()
		{
			// Restore call that was overwritten by trampoline.
			mov(rax, REL::Relocation<uintptr_t>(REL::Offset(0x1360EF0)).get());
			call(rax);

			// RAX = pointer to notification text (null-terminated).
			mov(rcx, rax);
			mov(rax, (uintptr_t)std::addressof(ShouldSkipNotification));
			call(rax);

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

	SKSE::Init(a_skse);

	Install();

	return true;
}
