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
		PEHeaders m_Headers;
		std::vector<PESection> m_Sections;
	};
}
