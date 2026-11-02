#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

//
// A PE image file as it is on disk (an executable, a DLL, a driver): its headers, sections, imports (the delay-loaded
// ones too) and exports. Load reads the file; Parse takes the bytes, so a test can hand it any buffer. Every offset,
// count and string is checked against the buffer (a file can be anything): what doesn't fit is left out, and a file
// whose headers don't parse gives nothing. No exceptions; no elevation.
//
namespace WinSys {
	struct PEDataDirectory {
		uint32_t Rva{ 0 }, Size{ 0 };
	};

	struct PEHeaders {
		bool Is64{ false };					// PE32+ (IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		uint16_t Machine{ 0 };				// IMAGE_FILE_MACHINE_*
		uint16_t NumberOfSections{ 0 };
		uint32_t TimeDateStamp{ 0 };		// seconds since 1970 (or a hash, for reproducible builds)
		uint16_t Characteristics{ 0 };		// IMAGE_FILE_*
		uint8_t LinkerMajor{ 0 }, LinkerMinor{ 0 };
		uint32_t EntryPoint{ 0 };			// an RVA, 0 for none
		uint64_t ImageBase{ 0 };
		uint32_t SectionAlignment{ 0 }, FileAlignment{ 0 };
		uint16_t OsMajor{ 0 }, OsMinor{ 0 }, SubsystemMajor{ 0 }, SubsystemMinor{ 0 };
		uint32_t SizeOfImage{ 0 }, SizeOfHeaders{ 0 }, CheckSum{ 0 };
		uint16_t Subsystem{ 0 };			// IMAGE_SUBSYSTEM_*
		uint16_t DllCharacteristics{ 0 };	// IMAGE_DLLCHARACTERISTICS_*
		uint64_t StackReserve{ 0 }, StackCommit{ 0 }, HeapReserve{ 0 }, HeapCommit{ 0 };
		std::vector<PEDataDirectory> Directories;	// IMAGE_DIRECTORY_ENTRY_* (as many as the header has, at most 16)
	};

	struct PESection {
		std::string Name;					// up to 8 characters
		uint32_t VirtualAddress{ 0 }, VirtualSize{ 0 };
		uint32_t RawOffset{ 0 }, RawSize{ 0 };	// in the file
		uint32_t Characteristics{ 0 };		// IMAGE_SCN_*
	};

	struct PEImportedFunction {
		std::string Name;					// empty for one imported by ordinal
		uint16_t Hint{ 0 };					// the name's index guess in the exporter's table
		uint16_t Ordinal{ 0 };				// for one imported by ordinal
		bool ByOrdinal{ false };
	};

	struct PEImportedLibrary {
		std::string Name;					// "KERNEL32.dll"
		bool Delayed{ false };				// delay-loaded (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
		std::vector<PEImportedFunction> Functions;
	};

	struct PEExportedFunction {
		std::string Name;					// empty for one exported by ordinal only
		uint32_t Ordinal{ 0 };
		uint32_t Rva{ 0 };
		std::string Forwarder;				// "NTDLL.RtlAcquireSRWLockExclusive" for a forwarded one (Rva into the exports)
	};

	struct PEExports {
		std::string Name;					// the name the image was linked as
		uint32_t Base{ 0 };					// the first ordinal
		std::vector<PEExportedFunction> Functions;	// by ordinal
	};

	// a debug directory entry (IMAGE_DEBUG_DIRECTORY)
	struct PEDebugEntry {
		uint32_t Type{ 0 };					// IMAGE_DEBUG_TYPE_*
		uint32_t TimeDateStamp{ 0 };
		uint32_t Size{ 0 };
		uint32_t Rva{ 0 }, RawOffset{ 0 };	// the data, in memory and in the file
		uint32_t Value{ 0 };				// EX_DLLCHARACTERISTICS: the flags (the data's first 32 bits); 0 otherwise
	};

	// the CodeView record of the PDB (RSDS): which symbols match the image
	struct PECodeView {
		GUID Signature{};
		uint32_t Age{ 0 };
		std::string PdbPath;				// as the linker wrote it (UTF-8)
	};

	// a resource (the resource directory's leaf: type, name, language)
	struct PEResource {
		uint16_t TypeId{ 0 };				// RT_* (0 for a named type)
		std::wstring Type;					// a named type's name, else empty
		uint16_t NameId{ 0 };				// 0 for a named resource
		std::wstring Name;
		uint16_t Language{ 0 };
		uint32_t Rva{ 0 }, Size{ 0 }, CodePage{ 0 };
	};

	// an icon of an icon group (RT_GROUP_ICON's GRPICONDIRENTRY): its RT_ICON resource holds the image
	struct PEIconEntry {
		uint32_t Width{ 0 }, Height{ 0 };	// 256 for the 0 the format stores
		uint16_t BitCount{ 0 };
		uint8_t ColorCount{ 0 };			// 0 for 256 colors or more
		uint32_t Size{ 0 };
		uint16_t IconId{ 0 };				// the RT_ICON resource's ID
	};

	// the CLR header (IMAGE_COR20_HEADER) and the metadata's version string: a .NET image
	struct PEDotNet {
		uint16_t RuntimeMajor{ 0 }, RuntimeMinor{ 0 };	// the header's (2.5 for every .NET image since 2.0)
		uint32_t Flags{ 0 };				// COMIMAGE_FLAGS_*
		uint32_t EntryPointToken{ 0 };		// a method token (or an RVA with COMIMAGE_FLAGS_NATIVE_ENTRYPOINT)
		uint32_t MetadataRva{ 0 }, MetadataSize{ 0 };
		std::string MetadataVersion;		// "v4.0.30319" (the runtime the image was built for; .NET Core and 5+ say the same)
		[[nodiscard]] bool IsILOnly() const;	// managed only (else mixed: C++/CLI)
	};

	class PEFile {
	public:
		// the file read (at most MaxFileSize) and parsed; nothing (the last error set: the file's, or
		// ERROR_BAD_EXE_FORMAT) if it can't be read or isn't a PE image
		[[nodiscard]] static std::optional<PEFile> Load(std::wstring const& path);
		[[nodiscard]] static std::optional<PEFile> Parse(std::vector<uint8_t> data);
		static constexpr size_t MaxFileSize = (size_t)1 << 30;

		[[nodiscard]] PEHeaders const& GetHeaders() const;
		[[nodiscard]] std::vector<PESection> const& GetSections() const;
		// parsed on each call: the import directory's libraries, then the delay import directory's
		[[nodiscard]] std::vector<PEImportedLibrary> GetImports() const;
		// none if the image exports nothing
		[[nodiscard]] std::optional<PEExports> GetExports() const;
		// the resource directory's leaves, by type, name and language (at most 65,536); none if it has none
		[[nodiscard]] std::vector<PEResource> GetResources() const;
		// a resource's bytes; empty if they aren't in the file
		[[nodiscard]] std::vector<uint8_t> GetResourceData(PEResource const& resource) const;
		[[nodiscard]] static PCWSTR ResourceTypeName(uint16_t type);	// "Icon", "Version", "Manifest"...
		// an icon group's icons (its data: GRPICONDIR and its entries); none if it isn't one or is cut short
		[[nodiscard]] std::vector<PEIconEntry> GetIconGroup(PEResource const& group) const;
		// the RT_ICON resource of an entry, preferring the group's language; none if it's missing
		[[nodiscard]] std::optional<PEResource> FindIcon(std::vector<PEResource> const& resources, uint16_t iconId, uint16_t language) const;
		// the CLR header, for a .NET image (managed or mixed); none for a native one
		[[nodiscard]] std::optional<PEDotNet> GetDotNet() const;
		[[nodiscard]] static std::wstring DotNetFlagsText(uint32_t flags);
		// the checksum as the loader and CheckSumMappedFile compute it (the file's 16-bit words summed with the carries
		// folded in, the header's checksum field left out, plus the file's length); drivers must match the header's
		[[nodiscard]] uint32_t ComputeChecksum() const;
		// the debug directory's entries
		[[nodiscard]] std::vector<PEDebugEntry> GetDebugEntries() const;
		// the CodeView entry's RSDS record (PDB 7.0); none if there's no such entry or it's another format
		[[nodiscard]] std::optional<PECodeView> GetCodeView() const;
		[[nodiscard]] static PCWSTR DebugTypeName(uint32_t type);	// "CodeView", "POGO", "Repro"...
		// an IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS value's flags: "CET compatible, ..."
		[[nodiscard]] static std::wstring ExDllCharacteristicsText(uint32_t flags);
		// an RVA's offset in the file: in the headers, or in a section's raw data; none if it's in neither
		[[nodiscard]] std::optional<uint32_t> RvaToOffset(uint32_t rva) const;

		[[nodiscard]] static PCWSTR MachineName(uint16_t machine);		// "x64", "ARM64"...
		[[nodiscard]] static PCWSTR SubsystemName(uint16_t subsystem);	// "Windows GUI", "Native"...
		[[nodiscard]] static PCWSTR DirectoryName(int index);			// "Export", "Import"...
		// the flags' names, separated by ", ": "Executable, Large address aware"
		[[nodiscard]] static std::wstring CharacteristicsText(uint16_t characteristics);
		[[nodiscard]] static std::wstring DllCharacteristicsText(uint16_t characteristics);
		[[nodiscard]] static std::wstring SectionCharacteristicsText(uint32_t characteristics);

	private:
		PEFile() = default;
		template<typename T>
		T const* At(size_t offset) const;
		// a NUL-terminated string at the offset, at most maxLength characters; empty if it doesn't end in the buffer
		std::string StringAt(size_t offset, size_t maxLength = 512) const;
		std::string StringAtRva(uint32_t rva, size_t maxLength = 512) const;
		// the functions of an import name table (thunks of the image's width) at the RVA
		std::vector<PEImportedFunction> ReadThunks(uint32_t rva) const;

		std::vector<uint8_t> m_Data;
		size_t m_ChecksumOffset{ 0 };	// the optional header's CheckSum field, in the file
		PEHeaders m_Headers;
		std::vector<PESection> m_Sections;
	};
}
