#include "pch.h"
#include "PEFile.h"
#include <wil/resource.h>

using namespace WinSys;

namespace {
	// limits on what a file claims, so a corrupt one can't make us loop or allocate forever
	constexpr size_t MaxSections = 96;			// the loader's own limit
	constexpr size_t MaxLibraries = 4096;
	constexpr size_t MaxThunks = 1 << 16;
	constexpr size_t MaxExports = 1 << 20;
}

template<typename T>
T const* PEFile::At(size_t offset) const {
	if (offset > m_Data.size() || m_Data.size() - offset < sizeof(T))
		return nullptr;
	return reinterpret_cast<T const*>(m_Data.data() + offset);
}

std::string PEFile::StringAt(size_t offset, size_t maxLength) const {
	if (offset >= m_Data.size())
		return {};
	auto start = reinterpret_cast<char const*>(m_Data.data() + offset);
	auto available = (std::min)(m_Data.size() - offset, maxLength);
	auto length = ::strnlen(start, available);
	// no NUL before the buffer's end: not a string; none within maxLength: its first maxLength characters
	if (length == available && available < maxLength)
		return {};
	return std::string(start, length);
}

std::string PEFile::StringAtRva(uint32_t rva, size_t maxLength) const {
	auto offset = RvaToOffset(rva);
	return offset ? StringAt(*offset, maxLength) : std::string();
}

std::optional<PEFile> PEFile::Load(std::wstring const& path) {
	wil::unique_hfile file(::CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr));
	if (!file)
		return std::nullopt;
	LARGE_INTEGER size;
	if (!::GetFileSizeEx(file.get(), &size))
		return std::nullopt;
	if (size.QuadPart < (LONGLONG)sizeof(IMAGE_DOS_HEADER) || (uint64_t)size.QuadPart > MaxFileSize) {
		::SetLastError(ERROR_BAD_EXE_FORMAT);
		return std::nullopt;
	}
	std::vector<uint8_t> data((size_t)size.QuadPart);
	size_t total = 0;
	while (total < data.size()) {
		DWORD read = 0;
		auto chunk = (DWORD)(std::min)(data.size() - total, (size_t)1 << 24);
		if (!::ReadFile(file.get(), data.data() + total, chunk, &read, nullptr))
			return std::nullopt;
		if (read == 0)
			break;
		total += read;
	}
	data.resize(total);
	return Parse(std::move(data));
}

std::optional<PEFile> PEFile::Parse(std::vector<uint8_t> data) {
	PEFile pe;
	pe.m_Data = std::move(data);
	auto fail = [] {
		::SetLastError(ERROR_BAD_EXE_FORMAT);
		return std::nullopt;
	};
	auto dos = pe.At<IMAGE_DOS_HEADER>(0);
	if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < 0)
		return fail();
	size_t ntOffset = (size_t)dos->e_lfanew;
	auto signature = pe.At<DWORD>(ntOffset);
	auto fileHeader = pe.At<IMAGE_FILE_HEADER>(ntOffset + sizeof(DWORD));
	if (!signature || *signature != IMAGE_NT_SIGNATURE || !fileHeader)
		return fail();
	auto optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	auto magic = pe.At<WORD>(optionalOffset);
	if (!magic)
		return fail();

	auto& h = pe.m_Headers;
	h.Machine = fileHeader->Machine;
	h.NumberOfSections = fileHeader->NumberOfSections;
	h.TimeDateStamp = fileHeader->TimeDateStamp;
	h.Characteristics = fileHeader->Characteristics;
	DWORD directories = 0;
	IMAGE_DATA_DIRECTORY const* directory = nullptr;
	size_t optionalSize = fileHeader->SizeOfOptionalHeader;
	auto fill = [&](auto const* o) {
		h.LinkerMajor = o->MajorLinkerVersion;
		h.LinkerMinor = o->MinorLinkerVersion;
		h.EntryPoint = o->AddressOfEntryPoint;
		h.ImageBase = o->ImageBase;
		h.SectionAlignment = o->SectionAlignment;
		h.FileAlignment = o->FileAlignment;
		h.OsMajor = o->MajorOperatingSystemVersion;
		h.OsMinor = o->MinorOperatingSystemVersion;
		h.SubsystemMajor = o->MajorSubsystemVersion;
		h.SubsystemMinor = o->MinorSubsystemVersion;
		h.SizeOfImage = o->SizeOfImage;
		h.SizeOfHeaders = o->SizeOfHeaders;
		h.CheckSum = o->CheckSum;
		h.Subsystem = o->Subsystem;
		h.DllCharacteristics = o->DllCharacteristics;
		h.StackReserve = o->SizeOfStackReserve;
		h.StackCommit = o->SizeOfStackCommit;
		h.HeapReserve = o->SizeOfHeapReserve;
		h.HeapCommit = o->SizeOfHeapCommit;
		// the directories the header has room for, at most 16
		auto fixed = offsetof(std::remove_pointer_t<decltype(o)>, DataDirectory);
		auto room = optionalSize > fixed ? (optionalSize - fixed) / sizeof(IMAGE_DATA_DIRECTORY) : 0;
		directories = (DWORD)(std::min)({ (size_t)o->NumberOfRvaAndSizes, room, (size_t)IMAGE_NUMBEROF_DIRECTORY_ENTRIES });
		directory = o->DataDirectory;
	};
	if (*magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		auto o = pe.At<IMAGE_OPTIONAL_HEADER64>(optionalOffset);
		if (!o)
			return fail();
		h.Is64 = true;
		fill(o);
	}
	else if (*magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		auto o = pe.At<IMAGE_OPTIONAL_HEADER32>(optionalOffset);
		if (!o)
			return fail();
		fill(o);
	}
	else
		return fail();
	for (DWORD i = 0; i < directories; i++)
		h.Directories.push_back({ directory[i].VirtualAddress, directory[i].Size });

	auto sectionOffset = optionalOffset + optionalSize;
	for (size_t i = 0; i < (std::min)((size_t)h.NumberOfSections, MaxSections); i++) {
		auto s = pe.At<IMAGE_SECTION_HEADER>(sectionOffset + i * sizeof(IMAGE_SECTION_HEADER));
		if (!s)
			break;
		PESection section;
		section.Name.assign(reinterpret_cast<char const*>(s->Name), ::strnlen(reinterpret_cast<char const*>(s->Name), IMAGE_SIZEOF_SHORT_NAME));
		section.VirtualAddress = s->VirtualAddress;
		section.VirtualSize = s->Misc.VirtualSize;
		section.RawOffset = s->PointerToRawData;
		section.RawSize = s->SizeOfRawData;
		section.Characteristics = s->Characteristics;
		pe.m_Sections.push_back(std::move(section));
	}
	return pe;
}

PEHeaders const& PEFile::GetHeaders() const {
	return m_Headers;
}

std::vector<PESection> const& PEFile::GetSections() const {
	return m_Sections;
}

std::optional<uint32_t> PEFile::RvaToOffset(uint32_t rva) const {
	// in the headers (as the loader maps them: the file's start)
	if (rva < m_Headers.SizeOfHeaders && rva < m_Data.size())
		return rva;
	for (auto& s : m_Sections) {
		// the loader rounds the raw offset down to 512 bytes
		auto raw = s.RawOffset & ~0x1FFu;
		auto size = s.VirtualSize ? (std::min)(s.VirtualSize, s.RawSize) : s.RawSize;
		if (rva >= s.VirtualAddress && rva - s.VirtualAddress < size) {
			uint64_t offset = (uint64_t)raw + (rva - s.VirtualAddress);
			if (offset < m_Data.size())
				return (uint32_t)offset;
			return std::nullopt;
		}
	}
	return std::nullopt;
}

std::vector<PEImportedFunction> PEFile::ReadThunks(uint32_t rva) const {
	std::vector<PEImportedFunction> functions;
	auto offset = RvaToOffset(rva);
	if (!offset)
		return functions;
	auto width = m_Headers.Is64 ? sizeof(uint64_t) : sizeof(uint32_t);
	for (size_t i = 0; i < MaxThunks; i++) {
		uint64_t thunk;
		if (m_Headers.Is64) {
			auto p = At<uint64_t>(*offset + i * width);
			if (!p)
				break;
			thunk = *p;
		}
		else {
			auto p = At<uint32_t>(*offset + i * width);
			if (!p)
				break;
			thunk = *p;
		}
		if (thunk == 0)
			break;
		PEImportedFunction f;
		bool byOrdinal = m_Headers.Is64 ? (thunk & IMAGE_ORDINAL_FLAG64) != 0 : (thunk & IMAGE_ORDINAL_FLAG32) != 0;
		if (byOrdinal) {
			f.ByOrdinal = true;
			f.Ordinal = (uint16_t)(thunk & 0xFFFF);
		}
		else {
			// IMAGE_IMPORT_BY_NAME: the hint, then the name
			auto nameOffset = RvaToOffset((uint32_t)thunk);
			if (auto hint = nameOffset ? At<uint16_t>(*nameOffset) : nullptr) {
				f.Hint = *hint;
				f.Name = StringAt(*nameOffset + sizeof(uint16_t));
			}
		}
		functions.push_back(std::move(f));
	}
	return functions;
}

std::vector<PEImportedLibrary> PEFile::GetImports() const {
	std::vector<PEImportedLibrary> libraries;
	auto& dirs = m_Headers.Directories;
	if (dirs.size() > IMAGE_DIRECTORY_ENTRY_IMPORT && dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Rva) {
		if (auto offset = RvaToOffset(dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].Rva)) {
			for (size_t i = 0; i < MaxLibraries; i++) {
				auto d = At<IMAGE_IMPORT_DESCRIPTOR>(*offset + i * sizeof(IMAGE_IMPORT_DESCRIPTOR));
				if (!d || (d->Name == 0 && d->FirstThunk == 0))
					break;
				PEImportedLibrary library;
				library.Name = StringAtRva(d->Name);
				// the name table, else (bound or old images) the address table, which holds the same before binding
				library.Functions = ReadThunks(d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk);
				libraries.push_back(std::move(library));
			}
		}
	}
	if (dirs.size() > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT && dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Rva) {
		if (auto offset = RvaToOffset(dirs[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Rva)) {
			for (size_t i = 0; i < MaxLibraries; i++) {
				auto d = At<IMAGE_DELAYLOAD_DESCRIPTOR>(*offset + i * sizeof(IMAGE_DELAYLOAD_DESCRIPTOR));
				if (!d || d->DllNameRVA == 0)
					break;
				// old (VC6) descriptors hold addresses, not RVAs
				auto toRva = [&](DWORD value) -> uint32_t {
					if (d->Attributes.RvaBased || value == 0)
						return value;
					return value >= m_Headers.ImageBase ? (uint32_t)(value - m_Headers.ImageBase) : 0;
				};
				PEImportedLibrary library;
				library.Delayed = true;
				library.Name = StringAtRva(toRva(d->DllNameRVA));
				library.Functions = ReadThunks(toRva(d->ImportNameTableRVA));
				libraries.push_back(std::move(library));
			}
		}
	}
	return libraries;
}

std::optional<PEExports> PEFile::GetExports() const {
	auto& dirs = m_Headers.Directories;
	if (dirs.size() <= IMAGE_DIRECTORY_ENTRY_EXPORT || dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Rva == 0)
		return std::nullopt;
	auto dirRva = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Rva, dirSize = dirs[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	auto offset = RvaToOffset(dirRva);
	auto e = offset ? At<IMAGE_EXPORT_DIRECTORY>(*offset) : nullptr;
	if (!e)
		return std::nullopt;
	PEExports exports;
	exports.Name = StringAtRva(e->Name);
	exports.Base = e->Base;
	auto count = (std::min)((size_t)e->NumberOfFunctions, MaxExports);
	auto functionsOffset = RvaToOffset(e->AddressOfFunctions);
	if (!functionsOffset)
		return exports;
	// the names, by function index
	std::vector<std::string> names(count);
	auto namesOffset = RvaToOffset(e->AddressOfNames), ordinalsOffset = RvaToOffset(e->AddressOfNameOrdinals);
	if (namesOffset && ordinalsOffset)
		for (size_t i = 0; i < (std::min)((size_t)e->NumberOfNames, MaxExports); i++) {
			auto nameRva = At<uint32_t>(*namesOffset + i * sizeof(uint32_t));
			auto index = At<uint16_t>(*ordinalsOffset + i * sizeof(uint16_t));
			if (!nameRva || !index)
				break;
			if (*index < count)
				names[*index] = StringAtRva(*nameRva);
		}
	for (size_t i = 0; i < count; i++) {
		auto rva = At<uint32_t>(*functionsOffset + i * sizeof(uint32_t));
		if (!rva)
			break;
		if (*rva == 0)
			continue;	// a gap in the ordinals
		PEExportedFunction f;
		f.Ordinal = (uint32_t)(exports.Base + i);
		f.Rva = *rva;
		f.Name = std::move(names[i]);
		// an RVA inside the export directory is a forwarder's "DLL.Function" string
		if (*rva >= dirRva && *rva - dirRva < dirSize)
			f.Forwarder = StringAtRva(*rva);
		exports.Functions.push_back(std::move(f));
	}
	return exports;
}

std::vector<PEDebugEntry> PEFile::GetDebugEntries() const {
	std::vector<PEDebugEntry> entries;
	auto& dirs = m_Headers.Directories;
	if (dirs.size() <= IMAGE_DIRECTORY_ENTRY_DEBUG || dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Rva == 0)
		return entries;
	auto offset = RvaToOffset(dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Rva);
	if (!offset)
		return entries;
	auto count = (std::min)((size_t)dirs[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY), (size_t)64);
	for (size_t i = 0; i < count; i++) {
		auto d = At<IMAGE_DEBUG_DIRECTORY>(*offset + i * sizeof(IMAGE_DEBUG_DIRECTORY));
		if (!d)
			break;
		PEDebugEntry e;
		e.Type = d->Type;
		e.TimeDateStamp = d->TimeDateStamp;
		e.Size = d->SizeOfData;
		e.Rva = d->AddressOfRawData;
		e.RawOffset = d->PointerToRawData;
		if (e.Type == 20 && e.Size >= sizeof(uint32_t))	// IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
			if (auto value = At<uint32_t>(e.RawOffset))
				e.Value = *value;
		entries.push_back(e);
	}
	return entries;
}

std::optional<PECodeView> PEFile::GetCodeView() const {
	for (auto& e : GetDebugEntries()) {
		if (e.Type != IMAGE_DEBUG_TYPE_CODEVIEW || e.Size < 24)
			continue;
		// "RSDS", the GUID, the age, then the PDB's path (NUL-terminated); in the file at the raw offset
		auto magic = At<uint32_t>(e.RawOffset);
		auto guid = At<GUID>((size_t)e.RawOffset + 4);
		auto age = At<uint32_t>((size_t)e.RawOffset + 20);
		if (!magic || *magic != 'SDSR' || !guid || !age)
			continue;
		PECodeView cv;
		cv.Signature = *guid;
		cv.Age = *age;
		cv.PdbPath = StringAt((size_t)e.RawOffset + 24, (std::min)((size_t)e.Size - 24, (size_t)1024));
		return cv;
	}
	return std::nullopt;
}

PCWSTR PEFile::DebugTypeName(uint32_t type) {
	switch (type) {
		case IMAGE_DEBUG_TYPE_COFF: return L"COFF";
		case IMAGE_DEBUG_TYPE_CODEVIEW: return L"CodeView";
		case IMAGE_DEBUG_TYPE_FPO: return L"FPO";
		case IMAGE_DEBUG_TYPE_MISC: return L"Misc";
		case IMAGE_DEBUG_TYPE_EXCEPTION: return L"Exception";
		case IMAGE_DEBUG_TYPE_FIXUP: return L"Fixup";
		case IMAGE_DEBUG_TYPE_BORLAND: return L"Borland";
		case IMAGE_DEBUG_TYPE_CLSID: return L"CLSID";
		case 12: return L"VC Feature";			// IMAGE_DEBUG_TYPE_VC_FEATURE
		case 13: return L"POGO";				// IMAGE_DEBUG_TYPE_POGO
		case 14: return L"ILTCG";				// IMAGE_DEBUG_TYPE_ILTCG
		case 15: return L"MPX";
		case 16: return L"Repro";				// IMAGE_DEBUG_TYPE_REPRO: the build's hash, in place of the time stamp
		case 17: return L"Embedded Portable PDB";
		case 19: return L"PDB Checksum";
		case 20: return L"Extended DLL Characteristics";	// IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS
	}
	return L"Other";
}

PCWSTR PEFile::MachineName(uint16_t machine) {
	switch (machine) {
		case IMAGE_FILE_MACHINE_I386: return L"x86";
		case IMAGE_FILE_MACHINE_AMD64: return L"x64";
		case IMAGE_FILE_MACHINE_ARM64: return L"ARM64";
		case IMAGE_FILE_MACHINE_ARMNT: return L"ARM (Thumb-2)";
		case IMAGE_FILE_MACHINE_ARM: return L"ARM";
		case IMAGE_FILE_MACHINE_IA64: return L"IA-64";
		case 0xA641: return L"ARM64EC";	// IMAGE_FILE_MACHINE_ARM64EC
		case 0xA64E: return L"ARM64X";	// IMAGE_FILE_MACHINE_ARM64X
		case IMAGE_FILE_MACHINE_UNKNOWN: return L"Unknown";
	}
	return L"Other";
}

PCWSTR PEFile::SubsystemName(uint16_t subsystem) {
	switch (subsystem) {
		case IMAGE_SUBSYSTEM_NATIVE: return L"Native";
		case IMAGE_SUBSYSTEM_WINDOWS_GUI: return L"Windows GUI";
		case IMAGE_SUBSYSTEM_WINDOWS_CUI: return L"Windows Console";
		case IMAGE_SUBSYSTEM_POSIX_CUI: return L"POSIX Console";
		case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI: return L"Windows CE GUI";
		case IMAGE_SUBSYSTEM_EFI_APPLICATION: return L"EFI Application";
		case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER: return L"EFI Boot Service Driver";
		case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER: return L"EFI Runtime Driver";
		case IMAGE_SUBSYSTEM_EFI_ROM: return L"EFI ROM";
		case IMAGE_SUBSYSTEM_XBOX: return L"Xbox";
		case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION: return L"Windows Boot Application";
	}
	return L"Unknown";
}

PCWSTR PEFile::DirectoryName(int index) {
	static const PCWSTR names[] = {
		L"Export", L"Import", L"Resource", L"Exception", L"Security", L"Base Relocation", L"Debug", L"Architecture",
		L"Global Pointer", L"TLS", L"Load Configuration", L"Bound Import", L"Import Address Table", L"Delay Import",
		L"COM Descriptor (.NET)", L"Reserved",
	};
	return index >= 0 && index < (int)_countof(names) ? names[index] : L"";
}

namespace {
	template<typename T>
	std::wstring FlagsText(T value, std::initializer_list<std::pair<T, PCWSTR>> flags) {
		std::wstring text;
		for (auto& [flag, name] : flags)
			if ((value & flag) == flag && flag)
				text += (text.empty() ? L"" : L", ") + std::wstring(name);
		return text;
	}
}

std::wstring PEFile::CharacteristicsText(uint16_t c) {
	return FlagsText<uint16_t>(c, {
		{ IMAGE_FILE_EXECUTABLE_IMAGE, L"Executable" }, { IMAGE_FILE_DLL, L"DLL" }, { IMAGE_FILE_SYSTEM, L"System" },
		{ IMAGE_FILE_LARGE_ADDRESS_AWARE, L"Large address aware" }, { IMAGE_FILE_32BIT_MACHINE, L"32-bit" },
		{ IMAGE_FILE_RELOCS_STRIPPED, L"Relocations stripped" }, { IMAGE_FILE_DEBUG_STRIPPED, L"Debug info stripped" },
		{ IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP, L"Run from swap (removable)" }, { IMAGE_FILE_NET_RUN_FROM_SWAP, L"Run from swap (network)" },
		{ IMAGE_FILE_UP_SYSTEM_ONLY, L"Uniprocessor only" },
		});
}

std::wstring PEFile::DllCharacteristicsText(uint16_t c) {
	return FlagsText<uint16_t>(c, {
		{ IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, L"High entropy VA" }, { IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, L"ASLR" },
		{ IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, L"Force integrity" }, { IMAGE_DLLCHARACTERISTICS_NX_COMPAT, L"DEP" },
		{ IMAGE_DLLCHARACTERISTICS_NO_ISOLATION, L"No isolation" }, { IMAGE_DLLCHARACTERISTICS_NO_SEH, L"No SEH" },
		{ IMAGE_DLLCHARACTERISTICS_NO_BIND, L"No bind" }, { IMAGE_DLLCHARACTERISTICS_APPCONTAINER, L"AppContainer" },
		{ IMAGE_DLLCHARACTERISTICS_WDM_DRIVER, L"WDM driver" }, { IMAGE_DLLCHARACTERISTICS_GUARD_CF, L"Control Flow Guard" },
		{ IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, L"Terminal Server aware" },
		});
}

std::wstring PEFile::SectionCharacteristicsText(uint32_t c) {
	auto text = FlagsText<uint32_t>(c, {
		{ IMAGE_SCN_CNT_CODE, L"Code" }, { IMAGE_SCN_CNT_INITIALIZED_DATA, L"Initialized data" },
		{ IMAGE_SCN_CNT_UNINITIALIZED_DATA, L"Uninitialized data" }, { IMAGE_SCN_MEM_DISCARDABLE, L"Discardable" },
		{ IMAGE_SCN_MEM_SHARED, L"Shared" }, { IMAGE_SCN_MEM_NOT_PAGED, L"Not paged" },
		});
	// the protection, as the loader maps it
	std::wstring access = std::wstring(c & IMAGE_SCN_MEM_READ ? L"R" : L"") + (c & IMAGE_SCN_MEM_WRITE ? L"W" : L"") + (c & IMAGE_SCN_MEM_EXECUTE ? L"X" : L"");
	if (!access.empty())
		text = access + (text.empty() ? L"" : L": " + text);
	return text;
}

std::wstring PEFile::ExDllCharacteristicsText(uint32_t flags) {
	return FlagsText<uint32_t>(flags, {
		{ 0x01, L"CET compatible" },						// IMAGE_DLLCHARACTERISTICS_EX_CET_COMPAT
		{ 0x02, L"CET strict mode" },						// ..._CET_COMPAT_STRICT_MODE
		{ 0x04, L"CET: relaxed SetContext" },				// ..._CET_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE
		{ 0x08, L"CET: no dynamic APIs out of process" },	// ..._CET_DYNAMIC_APIS_ALLOW_IN_PROC_ONLY
		{ 0x40, L"Forward CFI compatible" },				// ..._FORWARD_CFI_COMPAT
		{ 0x80, L"Hot patch compatible" },					// ..._HOTPATCH_COMPATIBLE
		});
}
