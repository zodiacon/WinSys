#include "pch.h"
#include "ProcessIntegrity.h"
#include "ProcessMemory.h"
#include "PEFile.h"
#include <wil/resource.h>

using namespace WinSys;

namespace {
	// without std::format (see CLAUDE.md)
	std::wstring Hex(uint64_t value) {
		WCHAR text[24];
		::StringCchPrintf(text, _countof(text), L"0x%llX", value);
		return text;
	}

	std::wstring Widen(std::string const& text) {
		return std::wstring(text.begin(), text.end());
	}

	// the headers' bytes: at most this much (the section table is in them)
	constexpr size_t MaxHeaders = 64 * 1024;

	std::wstring GetImageFileNtName(HANDLE hProcess) {
		BYTE buffer[sizeof(UNICODE_STRING) + MAX_PATH * 4 * sizeof(WCHAR)];
		if (!NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessImageFileName, buffer, sizeof(buffer), nullptr)))
			return L"";
		auto name = reinterpret_cast<UNICODE_STRING const*>(buffer);
		return name->Buffer ? std::wstring(name->Buffer, name->Length / sizeof(WCHAR)) : L"";
	}

	wil::unique_hfile OpenNtPath(std::wstring const& ntPath, DWORD access) {
		auto path = L"\\\\?\\GLOBALROOT" + ntPath;
		return wil::unique_hfile(::CreateFile(path.c_str(), access, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			nullptr, OPEN_EXISTING, 0, nullptr));
	}

	// a file's identity (its volume and ID): two names of one file (a short 8.3 name, a hard link) have the same
	std::optional<FILE_ID_INFO> GetFileId(std::wstring const& ntPath) {
		auto file = OpenNtPath(ntPath, FILE_READ_ATTRIBUTES);
		FILE_ID_INFO id{};
		if (!file || !::GetFileInformationByHandleEx(file.get(), FileIdInfo, &id, sizeof(id)))
			return std::nullopt;
		return id;
	}

	bool SameFile(std::wstring const& ntPath1, std::wstring const& ntPath2) {
		auto id1 = GetFileId(ntPath1), id2 = GetFileId(ntPath2);
		return id1 && id2 && id1->VolumeSerialNumber == id2->VolumeSerialNumber
			&& ::memcmp(&id1->FileId, &id2->FileId, sizeof(FILE_ID_128)) == 0;
	}

	// the mapped image is the process's own, taken from the image section the kernel made when it created the process
	// (before anyone could tamper): its file renamed or replaced since (a program that updates itself)
	bool IsOwnImageSection(HANDLE hProcess, PEFile const& inMemory, std::wstring const& mappedPath) {
		SECTION_IMAGE_INFORMATION section{};
		if (!NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessImageInformation, &section, sizeof(section), nullptr)))
			return false;
		auto& h = inMemory.GetHeaders();
		LARGE_INTEGER size{};
		auto file = OpenNtPath(mappedPath, FILE_READ_ATTRIBUTES);
		if (!file || !::GetFileSizeEx(file.get(), &size))
			return false;
		return section.Machine == h.Machine && section.CheckSum == h.CheckSum && section.ImageCharacteristics == h.Characteristics
			&& section.DllCharacteristics == h.DllCharacteristics && section.SubSystemType == h.Subsystem
			&& section.ImageFileSize == (ULONG)size.QuadPart;
	}

	// the first bytes of the file, enough for the headers; empty with the last error if it can't be read
	std::vector<uint8_t> ReadFileHeaders(std::wstring const& ntPath, size_t size) {
		auto file = OpenNtPath(ntPath, GENERIC_READ);
		if (!file)
			return {};
		std::vector<uint8_t> data(size);
		DWORD read = 0;
		if (!::ReadFile(file.get(), data.data(), (DWORD)size, &read, nullptr))
			return {};
		data.resize(read);
		return data;
	}

	bool IsExecutable(DWORD protect) {
		return (protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
	}
}

PCWSTR ProcessIntegrity::StatusText(ImageIntegrityStatus status) {
	switch (status) {
		case ImageIntegrityStatus::Ok: return L"OK";
		case ImageIntegrityStatus::FileGone: return L"Image file gone";
		case ImageIntegrityStatus::ImagePrivate: return L"Image replaced by private memory";
		case ImageIntegrityStatus::DifferentFile: return L"Another file's image";
		case ImageIntegrityStatus::HeadersDiffer: return L"Image headers differ from the file";
	}
	return L"";
}

std::wstring ProcessIntegrity::CompareHeaders(PEFile const& memory, PEFile const& file) {
	auto& m = memory.GetHeaders();
	auto& f = file.GetHeaders();
	std::wstring diff;
	auto add = [&](PCWSTR what, uint64_t inMemory, uint64_t inFile) {
		if (inMemory == inFile)
			return;
		if (!diff.empty())
			diff += L"; ";
		diff += std::wstring(what) + L" " + Hex(inMemory) + L" in memory, " + Hex(inFile) + L" in the file";
	};
	add(L"machine", m.Machine, f.Machine);
	add(L"timestamp", m.TimeDateStamp, f.TimeDateStamp);
	add(L"entry point", m.EntryPoint, f.EntryPoint);
	add(L"image size", m.SizeOfImage, f.SizeOfImage);
	add(L"subsystem", m.Subsystem, f.Subsystem);
	add(L"sections", m.NumberOfSections, f.NumberOfSections);
	auto& ms = memory.GetSections();
	auto& fs = file.GetSections();
	for (size_t i = 0; i < (std::min)(ms.size(), fs.size()); i++) {
		auto& a = ms[i];
		auto& b = fs[i];
		if (a.Name != b.Name || a.VirtualAddress != b.VirtualAddress || a.VirtualSize != b.VirtualSize || a.Characteristics != b.Characteristics) {
			if (!diff.empty())
				diff += L"; ";
			diff += L"section " + std::to_wstring(i + 1) + L" (" + Widen(b.Name) + L") is " + Widen(a.Name) + L" at " + Hex(a.VirtualAddress)
				+ L" in memory";
			break;
		}
	}
	return diff;
}

ImageIntegrity ProcessIntegrity::CheckImage(HANDLE hProcess) {
	ImageIntegrity result;
	PROCESS_BASIC_INFORMATION info{};
	if (!NT_SUCCESS(::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), nullptr)) || !info.PebBaseAddress) {
		result.Detail = L"No PEB";
		return result;
	}
	// the native PEB: a WOW64 process's has the image base too
	uint64_t imageBase = 0;
	if (ProcessMemory::Read(hProcess, (uint64_t)info.PebBaseAddress + offsetof(PEB, ImageBaseAddress), &imageBase, sizeof(imageBase)) != sizeof(imageBase)
		|| imageBase == 0) {
		result.Detail = L"The PEB can't be read";
		return result;
	}
	result.ImageBase = imageBase;

	MEMORY_BASIC_INFORMATION mbi{};
	if (!::VirtualQueryEx(hProcess, (PVOID)imageBase, &mbi, sizeof(mbi))) {
		result.Detail = L"The image base can't be queried";
		return result;
	}
	if (mbi.State != MEM_COMMIT || mbi.Type != MEM_IMAGE) {
		result.Status = ImageIntegrityStatus::ImagePrivate;
		result.Detail = std::wstring(L"The image base ") + Hex(imageBase) + (mbi.State != MEM_COMMIT ? L" isn't committed"
			: mbi.Type == MEM_PRIVATE ? L" is private memory" : L" is a data file's view");
		return result;
	}

	auto fileName = GetImageFileNtName(hProcess);
	if (fileName.empty()) {
		result.Detail = L"The image file's name can't be queried";
		return result;
	}
	auto mapped = ProcessMemory::GetMappedFileName(hProcess, (void const*)imageBase);
	if (mapped.empty()) {
		// the section's file isn't there to name (a deleted or transacted one)
		result.Status = ImageIntegrityStatus::FileGone;
		result.Detail = L"The mapped image has no file name";
		return result;
	}

	std::vector<uint8_t> memory(4096);
	if (ProcessMemory::Read(hProcess, imageBase, memory.data(), memory.size()) != memory.size()) {
		result.Detail = L"The image's headers can't be read";
		return result;
	}
	auto inMemory = PEFile::Parse(memory);
	if (!inMemory) {
		result.Status = ImageIntegrityStatus::HeadersDiffer;
		result.Detail = L"The headers in memory aren't a PE image's";
		return result;
	}
	// a larger header (rare): read all of it, so the section table is there
	auto headerSize = (std::min)((size_t)inMemory->GetHeaders().SizeOfHeaders, MaxHeaders);
	if (headerSize > memory.size()) {
		memory.resize(headerSize);
		ProcessMemory::Read(hProcess, imageBase, memory.data(), memory.size());
		inMemory = PEFile::Parse(memory);
		if (!inMemory) {
			result.Status = ImageIntegrityStatus::HeadersDiffer;
			result.Detail = L"The headers in memory aren't a PE image's";
			return result;
		}
	}

	// the name the process was created with against the mapped file's (its name now): the same file by another name
	// (8.3, a hard link), the process's own file renamed since (the image section's facts the kernel kept match),
	// or another image put in its place
	if (::_wcsicmp(mapped.c_str(), fileName.c_str()) != 0 && !SameFile(mapped, fileName)) {
		if (!IsOwnImageSection(hProcess, *inMemory, mapped)) {
			result.Status = ImageIntegrityStatus::DifferentFile;
			result.Detail = mapped + L" is mapped at the image base";
			return result;
		}
		result.Detail = L"Renamed since the start: " + mapped;
	}

	// the file that's mapped, by its name now
	auto fileData = ReadFileHeaders(mapped, (std::max)(headerSize, memory.size()));
	if (fileData.empty()) {
		auto error = ::GetLastError();
		if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_DELETE_PENDING) {
			result.Status = ImageIntegrityStatus::FileGone;
			result.Detail = mapped + L" isn't there anymore";
		}
		else
			result.Detail = L"The image file can't be read (error " + std::to_wstring(error) + L")";
		return result;
	}
	auto inFile = PEFile::Parse(std::move(fileData));
	if (!inFile) {
		result.Status = ImageIntegrityStatus::HeadersDiffer;
		result.Detail = L"The file isn't a PE image now";
		return result;
	}
	if (auto diff = CompareHeaders(*inMemory, *inFile); !diff.empty()) {
		result.Status = ImageIntegrityStatus::HeadersDiffer;
		result.Detail = std::move(diff);
		return result;
	}
	result.Status = ImageIntegrityStatus::Ok;
	return result;
}

std::optional<ExecutableMemory> ProcessIntegrity::GetExecutableMemory(HANDLE hProcess) {
	MEMORY_BASIC_INFORMATION mbi;
	if (!::VirtualQueryEx(hProcess, nullptr, &mbi, sizeof(mbi)))
		return std::nullopt;
	ExecutableMemory memory;
	uint64_t address = 0;
	auto max = ProcessMemory::MaxAddress();
	while (address < max && ::VirtualQueryEx(hProcess, (PVOID)address, &mbi, sizeof(mbi))) {
		if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) && IsExecutable(mbi.Protect)) {
			if (mbi.Type == MEM_PRIVATE) {
				memory.PrivateRegions++;
				memory.PrivateBytes += mbi.RegionSize;
				if (mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))
					memory.WritableRegions++;
			}
			else if (mbi.Type == MEM_MAPPED) {
				memory.MappedRegions++;
				memory.MappedBytes += mbi.RegionSize;
			}
		}
		auto next = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
		if (next <= address)
			break;
		address = next;
	}
	return memory;
}
