#include "pe_utils.h"

#include <fstream>

namespace pe {

ImageView LoadFile(const std::wstring& path, std::wstring* error) {
    ImageView image;

    // std::ifstream with binary mode — simple and sufficient for lab tooling.
    // Production injectors often use CreateFileW + ReadFile to avoid CRT and
    // to control sharing flags more carefully.
    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file) {
        if (error) {
            *error = L"Failed to open DLL file: " + path;
        }
        return image;
    }

    const auto end = file.tellg();
    if (end <= 0) {
        if (error) {
            *error = L"DLL file is empty: " + path;
        }
        return image;
    }

    const auto size = static_cast<std::size_t>(end);
    image.bytes.resize(size);
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(image.bytes.data()),
                   static_cast<std::streamsize>(size))) {
        if (error) {
            *error = L"Failed to read DLL file: " + path;
        }
        image.bytes.clear();
        return image;
    }

    return image;
}

bool ValidatePe64Dll(const ImageView& image, std::wstring* error) {
    const auto* dos = DosHeader(image);
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) {
        if (error) {
            *error = L"Invalid DOS signature (not a PE file).";
        }
        return false;
    }

    const auto* nt = NtHeaders(image);
    if (!nt || nt->Signature != IMAGE_NT_SIGNATURE) {
        if (error) {
            *error = L"Invalid NT signature.";
        }
        return false;
    }

    if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        if (error) {
            *error = L"PE is not AMD64. This injector is x64-only.";
        }
        return false;
    }

    if ((nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
        if (error) {
            *error = L"PE is not marked as a DLL (IMAGE_FILE_DLL missing).";
        }
        return false;
    }

    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (error) {
            *error = L"Optional header is not PE32+ (64-bit).";
        }
        return false;
    }

    if (nt->OptionalHeader.SizeOfImage == 0) {
        if (error) {
            *error = L"SizeOfImage is zero.";
        }
        return false;
    }

    return true;
}

const IMAGE_DOS_HEADER* DosHeader(const ImageView& image) {
    return image.at<IMAGE_DOS_HEADER>(0);
}

const IMAGE_NT_HEADERS64* NtHeaders(const ImageView& image) {
    const auto* dos = DosHeader(image);
    if (!dos) {
        return nullptr;
    }
    return image.at<IMAGE_NT_HEADERS64>(static_cast<std::size_t>(dos->e_lfanew));
}

const IMAGE_SECTION_HEADER* FirstSection(const ImageView& image) {
    const auto* nt = NtHeaders(image);
    if (!nt) {
        return nullptr;
    }
    // IMAGE_FIRST_SECTION macro walks past the optional header.
    return IMAGE_FIRST_SECTION(nt);
}

WORD SectionCount(const ImageView& image) {
    const auto* nt = NtHeaders(image);
    return nt ? nt->FileHeader.NumberOfSections : 0;
}

DWORD RvaToFileOffset(const ImageView& image, DWORD rva) {
    const auto* section = FirstSection(image);
    const WORD count = SectionCount(image);
    if (!section || count == 0) {
        return 0;
    }

    for (WORD i = 0; i < count; ++i) {
        const DWORD va = section[i].VirtualAddress;
        const DWORD rawSize = section[i].SizeOfRawData;
        const DWORD virtSize = section[i].Misc.VirtualSize;
        const DWORD span = (rawSize > virtSize) ? rawSize : virtSize;

        if (rva >= va && rva < va + span) {
            // Convert RVA to file offset using PointerToRawData.
            return section[i].PointerToRawData + (rva - va);
        }
    }

    // Headers / non-section RVAs: treat as identity within SizeOfHeaders.
    const auto* nt = NtHeaders(image);
    if (nt && rva < nt->OptionalHeader.SizeOfHeaders) {
        return rva;
    }
    return 0;
}

const IMAGE_DATA_DIRECTORY* DataDirectory(const ImageView& image, unsigned index) {
    const auto* nt = NtHeaders(image);
    if (!nt || index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        return nullptr;
    }
    return &nt->OptionalHeader.DataDirectory[index];
}

FARPROC ResolveExportByName(HMODULE localModule, const char* name) {
    // GetProcAddress is fine for resolving exports of modules already loaded
    // in *this* process. For remote resolution we instead parse the target's
    // export directory via ReadProcessMemory (see process_utils / mapper).
    return ::GetProcAddress(localModule, name);
}

FARPROC ResolveExportByOrdinal(HMODULE localModule, WORD ordinal) {
    return ::GetProcAddress(localModule, reinterpret_cast<LPCSTR>(static_cast<ULONG_PTR>(ordinal)));
}

}  // namespace pe
