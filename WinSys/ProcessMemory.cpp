#include "pch.h"
#include "ProcessMemory.h"

using namespace WinSys;

namespace {
	// read in chunks this large (plus the pattern's length, so a match across chunks is found)
	const size_t ChunkSize = 1 << 20;

	uint8_t Fold(uint8_t b) {
		return b >= 'A' && b <= 'Z' ? uint8_t(b | 0x20) : b;
	}

	// the first match in the data, or SIZE_MAX
	size_t Search(uint8_t const* data, size_t count, uint8_t const* pattern, size_t size, bool ignoreCase) {
		if (count < size)
			return SIZE_MAX;
		auto last = count - size;
		if (!ignoreCase) {
			for (size_t i = 0; i <= last; ) {
				auto p = (uint8_t const*)::memchr(data + i, pattern[0], last - i + 1);
				if (!p)
					break;
				auto at = size_t(p - data);
				if (::memcmp(p, pattern, size) == 0)
					return at;
				i = at + 1;
			}
			return SIZE_MAX;
		}
		auto first = Fold(pattern[0]);
		for (size_t i = 0; i <= last; i++) {
			if (Fold(data[i]) != first)
				continue;
			size_t j = 1;
			while (j < size && Fold(data[i + j]) == Fold(pattern[j]))
				j++;
			if (j == size)
				return i;
		}
		return SIZE_MAX;
	}

	bool IsReadable(MEMORY_BASIC_INFORMATION const& mbi) {
		return mbi.State == MEM_COMMIT && mbi.Protect != 0 && (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
	}
}

std::optional<uint64_t> ProcessMemory::Find(HANDLE hProcess, uint8_t const* pattern, size_t size, uint64_t from, uint64_t to, bool ignoreCase) {
	if (!pattern || size == 0 || from >= to)
		return std::nullopt;
	auto buffer = std::make_unique<uint8_t[]>(ChunkSize + size);
	MEMORY_BASIC_INFORMATION mbi;
	for (auto address = from; address < to; ) {
		if (::VirtualQueryEx(hProcess, (void const*)address, &mbi, sizeof(mbi)) != sizeof(mbi))
			break;
		auto regionEnd = (uint64_t)mbi.BaseAddress + mbi.RegionSize;
		if (IsReadable(mbi)) {
			auto end = (std::min)(regionEnd, to);
			for (auto at = address; at < end; at += ChunkSize) {
				// the chunk, and what a match starting in it needs of the next
				auto count = (size_t)(std::min)((uint64_t)ChunkSize + size - 1, end - at);
				SIZE_T read = 0;
				if (!::ReadProcessMemory(hProcess, (void const*)at, buffer.get(), count, &read) && read == 0)
					break;
				if (auto i = Search(buffer.get(), read, pattern, size, ignoreCase); i != SIZE_MAX)
					return at + i;
			}
		}
		address = regionEnd;
	}
	return std::nullopt;
}

size_t ProcessMemory::Read(HANDLE hProcess, uint64_t address, void* buffer, size_t size) {
	::memset(buffer, 0, size);
	SIZE_T read = 0;
	if (::ReadProcessMemory(hProcess, (void const*)address, buffer, size, &read))
		return read;
	// page by page: some can't be read
	size_t total = 0;
	for (size_t offset = 0; offset < size; ) {
		auto pageEnd = ((address + offset) | 0xFFF) + 1;
		auto count = (size_t)(std::min)((uint64_t)(size - offset), pageEnd - (address + offset));
		if (::ReadProcessMemory(hProcess, (void const*)(address + offset), (uint8_t*)buffer + offset, count, &read))
			total += read;
		offset += count;
	}
	return total;
}

bool ProcessMemory::Write(HANDLE hProcess, uint64_t address, void const* data, size_t size) {
	SIZE_T written = 0;
	if (!::WriteProcessMemory(hProcess, (void*)address, data, size, &written))
		return false;
	if (written != size) {
		::SetLastError(ERROR_PARTIAL_COPY);
		return false;
	}
	return true;
}

uint64_t ProcessMemory::MaxAddress() {
	SYSTEM_INFO si;
	::GetNativeSystemInfo(&si);
	return (uint64_t)si.lpMaximumApplicationAddress;
}
