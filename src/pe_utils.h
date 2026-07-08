#pragma once
/*
 * pe_utils.h — Local PE parsing helpers for the manual mapper.
 *
 * These utilities operate on a DLL image that has already been read into
 * the injector's address space. They do NOT touch the remote process.
 *
 * Anticheat note: once the image is mapped remotely, many of the same
 * structures (headers, sections, import/reloc directories) become forensic
 * artifacts that scanners can validate against on-disk PE expectations.
 */

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace pe {

struct ImageView {
    std::vector<std::uint8_t> bytes;

    [[nodiscard]] bool empty() const noexcept { return bytes.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return bytes.size(); }
    [[nodiscard]] std::uint8_t* data() noexcept { return bytes.data(); }
    [[nodiscard]] const std::uint8_t* data() const noexcept { return bytes.data(); }

    template <typename T>
    [[nodiscard]] T* at(std::size_t offset) {
        if (offset + sizeof(T) > bytes.size()) {
            return nullptr;
        }
        return reinterpret_cast<T*>(bytes.data() + offset);
    }

    template <typename T>
    [[nodiscard]] const T* at(std::size_t offset) const {
        if (offset + sizeof(T) > bytes.size()) {
            return nullptr;
        }
        return reinterpret_cast<const T*>(bytes.data() + offset);
    }
};

// Load an entire file into memory. Returns empty ImageView on failure.
[[nodiscard]] ImageView LoadFile(const std::wstring& path, std::wstring* error);

// Validate DOS + NT headers and confirm this is a 64-bit DLL PE.
[[nodiscard]] bool ValidatePe64Dll(const ImageView& image, std::wstring* error);

[[nodiscard]] const IMAGE_DOS_HEADER* DosHeader(const ImageView& image);
[[nodiscard]] const IMAGE_NT_HEADERS64* NtHeaders(const ImageView& image);
[[nodiscard]] const IMAGE_SECTION_HEADER* FirstSection(const ImageView& image);
[[nodiscard]] WORD SectionCount(const ImageView& image);

// RVA -> file offset within the local (file-aligned) image buffer.
[[nodiscard]] DWORD RvaToFileOffset(const ImageView& image, DWORD rva);

// Convenience accessors for data directories.
[[nodiscard]] const IMAGE_DATA_DIRECTORY* DataDirectory(const ImageView& image, unsigned index);

// Resolve an exported function RVA from a module that is already mapped
 // in the *local* process (used when walking the target's loaded modules
 // via ReadProcessMemory of their export tables).
[[nodiscard]] FARPROC ResolveExportByName(HMODULE localModule, const char* name);
[[nodiscard]] FARPROC ResolveExportByOrdinal(HMODULE localModule, WORD ordinal);

}  // namespace pe
