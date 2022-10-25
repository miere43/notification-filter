#include <string_view>
#include <SKSE/SKSE.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <SimpleIni.h>
#include <xbyak/xbyak.h>
#include "Plugin.h"

using namespace std::literals;

namespace logger = SKSE::log;

namespace util
{
	using SKSE::stl::report_and_fail;
}

namespace
{
	constexpr auto PapyrusDebugNotificationID = REL::RelocationID(54612, 55269);
	constexpr auto GetNotificationTextID = REL::RelocationID(97497, 104285);

	enum class FilterType
	{
		All,
		Papyrus,
	};

	struct TextPattern
	{
		std::string text;
	};

	struct RegularExpressionPattern
	{
		std::regex regex;
		std::string originalString;
	};

	using AnyPattern = std::variant<TextPattern, RegularExpressionPattern>;

	struct PatternLoad
	{
		AnyPattern value;
		int order = 0;
	};

	struct Settings
	{
		bool enableLog = false;
		std::vector<AnyPattern> hidePatterns;
		std::vector<AnyPattern> showPatterns;
		FilterType filterType = FilterType::All;
	};
	static Settings settings;

	static void LogPatterns(const std::vector<AnyPattern>& patterns, const std::string_view& title)
	{
		if (patterns.size() == 0 || !settings.enableLog) {
			return;
		}
	
		logger::debug("{}"sv, title);
		int index = 0;
		for (const auto& pattern : patterns) {
			++index;
			if (std::holds_alternative<TextPattern>(pattern)) {
				const auto& text = std::get<TextPattern>(pattern);
				logger::debug("{}. Text \"{}\""sv, index, text.text);
			} else {
				const auto& regex = std::get<RegularExpressionPattern>(pattern);
				logger::debug("{}. Regular Expression \"{}\""sv, index, regex.originalString);
			}
		}
	}

	static std::vector<AnyPattern> LoadPatterns(const CSimpleIniA& ini, const char* plainKey, const char* regexKey)
	{
		std::vector<PatternLoad> patternLoads;

		std::list<CSimpleIniA::Entry> entries;
		ini.GetAllValues("Filters", plainKey, entries);

		for (const auto& entry : entries) {
			patternLoads.push_back({ TextPattern{ std::string(entry.pItem) }, entry.nOrder });
		}

		entries.clear();
		ini.GetAllValues("Filters", regexKey, entries);

		for (const auto& entry : entries) {
			std::string originalString(entry.pItem);
			std::regex pattern;
			try {
				pattern = std::regex(originalString, std::regex_constants::ECMAScript);
			}
			catch (const std::regex_error& e) {
				logger::error("Error parsing regular expression \"{}\": \"{}\""sv, originalString, e.what());
				continue;
			}

			patternLoads.push_back({ RegularExpressionPattern{ pattern, originalString }, entry.nOrder });
		}

		std::sort(patternLoads.begin(), patternLoads.end(), [](const PatternLoad& a, const PatternLoad& b) {
			return a.order > b.order;
		});

		std::vector<AnyPattern> patterns;
		patterns.reserve(patternLoads.size());
		for (const auto& pattern : patternLoads) {
			patterns.push_back(pattern.value);
		}
		
		return patterns;
	}

	static void LoadSettings(spdlog::logger& log)
	{
		CSimpleIniA ini;
		ini.SetUnicode(true);
		ini.SetMultiKey(true);

		auto rc = ini.LoadFile(L"Data/SKSE/Plugins/NotificationFilter.ini");
		if (rc < 0) {
			logger::error("Failed to read INI settings from Data/SKSE/Plugins/NotificationFilter.ini, using default settings (error code was {})", rc);
			return;
		}

		settings.enableLog = ini.GetBoolValue("General", "EnableLog", settings.enableLog);
		if (settings.enableLog) {
			log.set_level(spdlog::level::debug);
			log.flush_on(spdlog::level::debug);
		}

		const auto filterTypeString = ini.GetValue("General", "FilterType", "All");
		if (0 == _stricmp(filterTypeString, "Papyrus")) {
			settings.filterType = FilterType::Papyrus;
		} else if (0 == _stricmp(filterTypeString, "All")) {
			settings.filterType = FilterType::All;
		} else {
			logger::error(
				"Invalid value for \"FilterType\" option in section [General]. Expected string \"All\" or \"Papyrus\", got \"{}\". Using \"All\" instead"sv,
				filterTypeString
			);
		}

		settings.hidePatterns = LoadPatterns(ini, "Hide", "HideRegex");
		settings.showPatterns = LoadPatterns(ini, "Show", "ShowRegex");
	}

	static std::shared_ptr<spdlog::logger> InitializeLog()
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

		spdlog::set_default_logger(log);
		spdlog::set_pattern("%g(%#): [%^%l%$] %v"s);
		return log;
	}

	[[nodiscard]] static bool MatchPattern(const AnyPattern& pattern, const std::string_view& text)
	{
		if (std::holds_alternative<TextPattern>(pattern)) {
			const auto& textPattern = std::get<TextPattern>(pattern);
			return textPattern.text == text;
		}

		const auto& regexPattern = std::get<RegularExpressionPattern>(pattern);
		return std::regex_match(text.data(), regexPattern.regex);
	}

	[[nodiscard]] static const AnyPattern* MatchPatterns(const std::vector<AnyPattern>& patterns, const std::string_view& text)
	{
		for (const auto& pattern : patterns) {
			if (MatchPattern(pattern, text)) {
				return &pattern;
			}
		}
		return nullptr;
	}

	static void LogPatternMatch(const AnyPattern& pattern, const std::string_view& text, const std::string_view& showingOrHiding)
	{
		if (!settings.enableLog) {
			return;
		}

		if (std::holds_alternative<TextPattern>(pattern)) {
			const auto& textPattern = std::get<TextPattern>(pattern);
			logger::debug("{} notification \"{}\" because it matches text pattern \"{}\""sv, showingOrHiding, text, textPattern.text);
		} else {
			const auto& regexPattern = std::get<RegularExpressionPattern>(pattern);
			logger::debug("{} notification \"{}\" because it matches regular expression pattern \"{}\""sv, showingOrHiding, text, regexPattern.originalString);
		}
	}

	static bool ShouldSkipNotification(const char** textPtrRef)
	{
		const auto text = std::string_view(*textPtrRef);
		const auto hidePattern = MatchPatterns(settings.hidePatterns, text);
		if (hidePattern == nullptr) {
			logger::debug("Showing notification \"{}\" because it doesn't match any known hide patterns"sv, text);
			return false;
		}

		if (const auto showPattern = MatchPatterns(settings.showPatterns, text)) {
			LogPatternMatch(*showPattern, text, "Showing"sv);
			return false;
		}
		
		LogPatternMatch(*hidePattern, text, "Hiding"sv);
		return true;
	}

	// Hooks Papyrus Debug.Notification function.
	struct PapyrusDebugNotificationCode : Xbyak::CodeGenerator
	{
		PapyrusDebugNotificationCode()
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
			mov(rax, REL::Relocation<uintptr_t>(PapyrusDebugNotificationID, REL::VariantOffset(0x95, 0xD0, 0x95).offset()).get());
			jmp(rax);

			// Otherwise, jump back to normal control flow (show notification).
			L("ok");
			mov(rax, rcx); // Return notification text.
			mov(rcx, REL::Relocation<uintptr_t>(PapyrusDebugNotificationID, 0x56).get());
			jmp(rcx);
		}

		static void Install()
		{
			auto codeGen = new PapyrusDebugNotificationCode();
			auto codePtr = codeGen->getCode();

			SKSE::AllocTrampoline(20);

			// Replace call to GetNotificationText with our code.
			SKSE::GetTrampoline().write_branch<5>(REL::Relocation<uintptr_t>(PapyrusDebugNotificationID, 0x51).get(), codePtr);
		}
	};

	// Hooks native notification function (Papyrus calls it from Debug.Notification).
	struct NotificationCode : Xbyak::CodeGenerator
	{
		static bool Thunk(const char* a_notification, const char* a_soundToPlay, bool a_cancelIfAlreadyQueued)
		{
			(void*)a_soundToPlay;
			(void*)a_cancelIfAlreadyQueued;
			return ShouldSkipNotification(&a_notification);
		}

		NotificationCode()
		{
			push(rcx);
			push(rdx);
			push(r8);
			push(r9);
			push(r10);
			push(r11);

			sub(rsp, 0x20 + 0x08); // Add +0x08 to align to 16-byte boundary.
			mov(rax, (uintptr_t)std::addressof(Thunk));
			call(rax);
			add(rsp, 0x20 + 0x08);

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
			mov(rax, REL::Relocation<uintptr_t>(RE::Offset::DebugNotification, REL::VariantOffset(0x1DD, 0x35F, 0x1DD).offset()).get());
			jmp(rax);

			// Otherwise, jump back to normal control flow (show notification).
			L("ok");

			// Restore instructions overwritten by trampoline.
			push(rdi);
			push(r12);
			push(r13);

			mov(rax, REL::Relocation<uintptr_t>(RE::Offset::DebugNotification, 0x06).get());
			jmp(rax);
		}

		static void Install()
		{
			auto codeGen = new NotificationCode();
			auto codePtr = codeGen->getCode();

			SKSE::AllocTrampoline(20);
			SKSE::GetTrampoline().write_branch<5>(REL::Relocation<uintptr_t>(RE::Offset::DebugNotification).get(), codePtr);
		}
	};

	static std::string_view GetRuntimeString()
	{
		switch (REL::Module::GetRuntime()) {
		case REL::Module::Runtime::AE:
			return "Anniversary Edition"sv;
		case REL::Module::Runtime::SE:
			return "Special Edition"sv;
		case REL::Module::Runtime::VR:
			return "VR"sv;
		}
		return "Unknown"sv;
	}
}

extern "C" [[maybe_unused]] __declspec(dllexport) constinit auto SKSEPlugin_Version = []() noexcept {
	// @TODO: update CommonLibSSE and use constant from there.
	constexpr REL::Version RUNTIME_SSE_1_6_640(1, 6, 640, 0);
	constexpr REL::Version RUNTIME_SSE_1_6_659(1, 6, 659, 0); // GOG version, not tested
	
	SKSE::PluginVersionData v;

	v.PluginVersion(Plugin::VERSION);
	v.PluginName(Plugin::NAME);
	v.AuthorName("miere"sv);
	v.UsesAddressLibrary(true);
	v.UsesStructsPost629(true);
	v.HasNoStructUse(true);

	v.CompatibleVersions({
		SKSE::RUNTIME_SSE_1_6_629,
		RUNTIME_SSE_1_6_640,
		RUNTIME_SSE_1_6_659,
	});
	return v;
}();

extern "C" [[maybe_unused]] __declspec(dllexport) bool SKSEAPI SKSEPlugin_Query(const SKSE::QueryInterface*, SKSE::PluginInfo* pluginInfo)
{
	pluginInfo->name = Plugin::NAME.data();
	pluginInfo->infoVersion = SKSE::PluginInfo::kVersion;
	pluginInfo->version = Plugin::VERSION.pack();
	return true;
}

extern "C" [[maybe_unused]] __declspec(dllexport) bool SKSEAPI SKSEPlugin_Load(const SKSE::LoadInterface* skse)
{
	auto log = InitializeLog();
	logger::info("{} v{}"sv, Plugin::NAME, Plugin::VERSION.string());
	logger::info("Runtime: {}"sv, GetRuntimeString());

	LoadSettings(*log.get());
	logger::info(
		"Using settings: FilterType = {}, EnableLog = {}, {} hide patterns loaded, {} show patterns loaded"sv,
		settings.filterType == FilterType::All ? "All"sv : "Papyrus"sv,
		settings.enableLog,
		settings.hidePatterns.size(),
		settings.showPatterns.size()
	);
	if (log->level() >= spdlog::level::debug) {
		LogPatterns(settings.hidePatterns, "Loaded hide patterns:"sv);
		LogPatterns(settings.showPatterns, "Loaded show patterns:"sv);
	}

	SKSE::Init(skse);

	if (settings.hidePatterns.size() == 0) {
		logger::error("No hide patterns were registered"sv);
	}

	if (settings.hidePatterns.size()) {
		if (settings.filterType == FilterType::All) {
			NotificationCode::Install();
		} else {
			PapyrusDebugNotificationCode::Install();
		}
		logger::info("Patch was installed"sv);
	} else {
		logger::info("Patch was NOT installed because there are no hide patterns"sv);
	}

	return true;
}
