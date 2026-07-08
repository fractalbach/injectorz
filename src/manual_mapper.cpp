#include "manual_mapper.h"

#include "pe_utils.h"
#include "process_utils.h"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace mapper {
namespace {

void Log(const Options& opt, const wchar_t* msg) {
    if (opt.verbose) {
        std::wcout << L"[*] " << msg << L"\n";
    }
}

void LogHex(const Options& opt, const wchar_t* label, std::uintptr_t value) {
    if (opt.verbose) {
        std::wcout << L"[*] " << label << L" 0x" << std::hex << value << std::dec << L"\n";
    }
}

void LogFail(const Options& opt, const std::wstring& msg) {
    if (opt.verbose) {
        std::wcerr << L"[!] " << msg << L"\n";
    }
}

// Convert PE section Characteristics to a VirtualProtect page protection.
DWORD SectionProtection(DWORD characteristics) {
    const bool exec = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool read = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool write = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (exec && write) {
        // RWX sections are rare in legitimate images and highly suspicious.
        return PAGE_EXECUTE_READWRITE;
    }
    if (exec && read) {
        return PAGE_EXECUTE_READ;
    }
    if (exec) {
        return PAGE_EXECUTE;
    }
    if (write && read) {
        return PAGE_READWRITE;
    }
    if (read) {
        return PAGE_READONLY;
    }
    return PAGE_NOACCESS;
}

/*
 * Generic x64 call stub executed in the remote process.
 *
 * CreateRemoteThread only supplies one parameter (RCX). DllMain and TLS
 * callbacks need (HMODULE, DWORD reason, LPVOID reserved). This stub reads a
 * small descriptor and performs the call with the correct arguments.
 *
 * Descriptor layout (CallStubData):
 *   +0x00  UINT64 function   ; absolute address to call
 *   +0x08  UINT64 hmodule    ; first argument
 *
 * Assembly:
 *   mov  rbx, rcx
 *   mov  rax, [rbx]          ; function
 *   mov  rcx, [rbx+8]        ; hmodule
 *   mov  edx, 1              ; DLL_PROCESS_ATTACH
 *   xor  r8, r8              ; lpReserved = nullptr
 *   sub  rsp, 0x28           ; shadow space + alignment
 *   call rax
 *   add  rsp, 0x28
 *   ret
 *
 * DETECTION: Thread start address in a tiny MEM_PRIVATE RX page that is not
 * backed by any LDR module is a classic remote-thread+shellcode signature.
 * Kernel thread-notify routines see the start address immediately.
 */
#pragma pack(push, 1)
struct CallStubData {
    std::uint64_t function = 0;
    std::uint64_t hmodule = 0;
};
#pragma pack(pop)

std::vector<std::uint8_t> BuildCallStubBytes() {
    // clang-format off
    return {
        0x48, 0x89, 0xCB,                   // mov rbx, rcx
        0x48, 0x8B, 0x03,                   // mov rax, [rbx]
        0x48, 0x8B, 0x4B, 0x08,             // mov rcx, [rbx+8]
        0xBA, 0x01, 0x00, 0x00, 0x00,       // mov edx, 1
        0x4D, 0x31, 0xC0,                   // xor r8, r8
        0x48, 0x83, 0xEC, 0x28,             // sub rsp, 0x28
        0xFF, 0xD0,                         // call rax
        0x48, 0x83, 0xC4, 0x28,             // add rsp, 0x28
        0xC3                                // ret
    };
    // clang-format on
}

bool ApplyRelocations(HANDLE process, const pe::ImageView& image, std::uintptr_t remoteBase,
                      std::uintptr_t preferredBase, const Options& opt, std::wstring* error) {
    /*
     * Base relocations adjust absolute addresses when the image could not
     * be loaded at OptionalHeader.ImageBase.
     *
     * Delta = actualBase - preferredBase
     * For each IMAGE_REL_BASED_DIR64 entry: *(UINT64*)(base+rva) += delta
     *
     * DETECTION:
     *   - Preferred base free but image elsewhere can look odd (usually ASLR).
     *   - After header wipe, reloc metadata is gone but patched pointers remain.
     */
    const auto* nt = pe::NtHeaders(image);
    const auto& relocDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    const std::int64_t delta =
        static_cast<std::int64_t>(remoteBase) - static_cast<std::int64_t>(preferredBase);

    if (delta == 0) {
        Log(opt, L"Image allocated at preferred base — no relocations needed.");
        return true;
    }

    if (relocDir.VirtualAddress == 0 || relocDir.Size == 0) {
        if (error) {
            *error = L"Image requires relocation but has no .reloc directory "
                     L"(not relocatable).";
        }
        return false;
    }

    LogHex(opt, L"Relocation delta:", static_cast<std::uintptr_t>(delta));

    const DWORD fileOff = pe::RvaToFileOffset(image, relocDir.VirtualAddress);
    if (fileOff == 0 && relocDir.VirtualAddress != 0) {
        if (error) {
            *error = L"Failed to map reloc directory RVA to file offset.";
        }
        return false;
    }

    const std::uint8_t* relocBase = image.data() + fileOff;
    const std::uint8_t* relocEnd = relocBase + relocDir.Size;

    while (relocBase < relocEnd) {
        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(relocBase);
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
            break;
        }

        const DWORD entryCount =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        const auto* entries = reinterpret_cast<const WORD*>(block + 1);

        for (DWORD i = 0; i < entryCount; ++i) {
            const WORD type = static_cast<WORD>(entries[i] >> 12);
            const WORD offset = static_cast<WORD>(entries[i] & 0x0FFF);

            if (type == IMAGE_REL_BASED_ABSOLUTE) {
                continue;  // Padding
            }
            if (type != IMAGE_REL_BASED_DIR64) {
                if (error) {
                    *error = L"Unsupported relocation type (expected DIR64).";
                }
                return false;
            }

            const std::uintptr_t patchAddr = remoteBase + block->VirtualAddress + offset;
            std::uint64_t value = 0;
            if (!proc::ReadMemory(process, patchAddr, &value, sizeof(value), error)) {
                return false;
            }
            value = static_cast<std::uint64_t>(static_cast<std::int64_t>(value) + delta);
            if (!proc::WriteMemory(process, patchAddr, &value, sizeof(value), error)) {
                return false;
            }
        }

        relocBase += block->SizeOfBlock;
    }

    Log(opt, L"Base relocations applied.");
    return true;
}

bool ResolveImports(HANDLE process, DWORD pid, const pe::ImageView& image,
                    std::uintptr_t remoteBase, const Options& opt, std::wstring* error) {
    /*
     * Walk IMAGE_IMPORT_DESCRIPTOR array and fill the IAT (FirstThunk).
     *
     * For each imported DLL:
     *   - Locate the module base in the *target* process
     *   - For each thunk: resolve by name or ordinal to a remote VA
     *   - Write the VA into the corresponding IAT slot
     *
     * We do NOT call LoadLibrary in the target. Missing dependencies fail.
     *
     * DETECTION:
     *   - IAT in private memory pointing at ntdll/kernel32 exports
     *   - Clustered RPM/WPM during resolve
     *   - Code executing from a base absent from PEB LDR
     */
    const auto* nt = pe::NtHeaders(image);
    const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.VirtualAddress == 0) {
        Log(opt, L"No imports — skipping IAT resolution.");
        return true;
    }

    const DWORD importFileOff = pe::RvaToFileOffset(image, importDir.VirtualAddress);
    auto* descriptor =
        reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(image.data() + importFileOff);

    for (; descriptor->Name != 0; ++descriptor) {
        const DWORD nameOff = pe::RvaToFileOffset(image, descriptor->Name);
        const char* dllNameA = reinterpret_cast<const char*>(image.data() + nameOff);

        std::wstring dllNameW;
        for (const char* p = dllNameA; *p; ++p) {
            dllNameW.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*p)));
        }

        if (opt.verbose) {
            std::wcout << L"[*] Resolving imports from " << dllNameW << L"\n";
        }

        std::wstring modErr;
        const std::uintptr_t modBase = proc::FindModuleBase(pid, dllNameW, &modErr);
        if (!modBase) {
            if (error) {
                *error = L"Dependency not loaded in target: " + dllNameW + L" (" + modErr + L")";
            }
            return false;
        }

        // OriginalFirstThunk = ILT (names/ordinals); FirstThunk = IAT (patched).
        const DWORD iltRva = descriptor->OriginalFirstThunk ? descriptor->OriginalFirstThunk
                                                            : descriptor->FirstThunk;
        const DWORD iatRva = descriptor->FirstThunk;

        for (DWORD index = 0;; ++index) {
            IMAGE_THUNK_DATA64 thunk{};
            const DWORD thunkFileOff =
                pe::RvaToFileOffset(image, iltRva + index * sizeof(IMAGE_THUNK_DATA64));
            std::memcpy(&thunk, image.data() + thunkFileOff, sizeof(thunk));
            if (thunk.u1.AddressOfData == 0) {
                break;
            }

            std::uintptr_t func = 0;
            std::wstring resolveErr;

            if (thunk.u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                const WORD ordinal = static_cast<WORD>(IMAGE_ORDINAL64(thunk.u1.Ordinal));
                func = proc::ResolveRemoteExportByOrdinal(process, modBase, ordinal, &resolveErr);
            } else {
                const DWORD ibnRva = static_cast<DWORD>(thunk.u1.AddressOfData);
                const DWORD ibnOff = pe::RvaToFileOffset(image, ibnRva);
                const auto* ibn =
                    reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(image.data() + ibnOff);
                func = proc::ResolveRemoteExport(process, modBase, ibn->Name, &resolveErr);
            }

            if (!func) {
                if (error) {
                    *error = L"Failed to resolve import from " + dllNameW + L": " + resolveErr;
                }
                return false;
            }

            const std::uintptr_t iatSlot = remoteBase + iatRva + index * sizeof(std::uint64_t);
            if (!proc::WriteMemory(process, iatSlot, &func, sizeof(func), error)) {
                return false;
            }
        }
    }

    Log(opt, L"IAT resolved.");
    return true;
}

bool MapSections(HANDLE process, const pe::ImageView& image, std::uintptr_t remoteBase,
                 const Options& opt, std::wstring* error) {
    const auto* nt = pe::NtHeaders(image);

    // Copy headers (DOS + NT + section table). May be wiped later for stealth.
    if (!proc::WriteMemory(process, remoteBase, image.data(), nt->OptionalHeader.SizeOfHeaders,
                           error)) {
        return false;
    }
    Log(opt, L"PE headers written to remote image.");

    const auto* section = pe::FirstSection(image);
    const WORD count = pe::SectionCount(image);

    for (WORD i = 0; i < count; ++i) {
        if (section[i].SizeOfRawData == 0) {
            continue;  // Uninitialized data; already zero from VirtualAllocEx.
        }
        if (static_cast<std::size_t>(section[i].PointerToRawData) + section[i].SizeOfRawData >
            image.size()) {
            if (error) {
                *error = L"Section raw data exceeds file size.";
            }
            return false;
        }

        const std::uintptr_t dest = remoteBase + section[i].VirtualAddress;
        if (!proc::WriteMemory(process, dest, image.data() + section[i].PointerToRawData,
                               section[i].SizeOfRawData, error)) {
            return false;
        }

        if (opt.verbose) {
            char name[9]{};
            std::memcpy(name, section[i].Name, 8);
            std::wcout << L"[*] Mapped section " << name << L" -> 0x" << std::hex << dest
                       << std::dec << L" (" << section[i].SizeOfRawData << L" bytes)\n";
        }
    }

    return true;
}

bool ApplySectionProtections(HANDLE process, const pe::ImageView& image, std::uintptr_t remoteBase,
                             const Options& opt, std::wstring* error) {
    /*
     * Match PE section characteristics to page protections.
     *
     * DETECTION: Whole-image RWX is an easy signature. Proper RX/RW/RO is more
     * loader-like, but the VAD remains MEM_PRIVATE (not MEM_IMAGE).
     */
    const auto* section = pe::FirstSection(image);
    const WORD count = pe::SectionCount(image);
    const auto* nt = pe::NtHeaders(image);

    SYSTEM_INFO si{};
    ::GetSystemInfo(&si);
    const std::size_t pageSize = si.dwPageSize;

    DWORD oldProt = 0;
    if (!proc::ProtectMemory(process, reinterpret_cast<LPVOID>(remoteBase),
                             nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProt, error)) {
        return false;
    }

    for (WORD i = 0; i < count; ++i) {
        const DWORD prot = SectionProtection(section[i].Characteristics);
        std::size_t size = section[i].Misc.VirtualSize;
        if (size == 0) {
            size = section[i].SizeOfRawData;
        }
        if (size == 0) {
            continue;
        }

        size = (size + pageSize - 1) & ~(pageSize - 1);

        if (!proc::ProtectMemory(process,
                                 reinterpret_cast<LPVOID>(remoteBase + section[i].VirtualAddress),
                                 size, prot, &oldProt, error)) {
            return false;
        }

        if (opt.verbose && prot == PAGE_EXECUTE_READWRITE) {
            std::wcout << L"[!] Warning: section has RWX characteristics — highly suspicious "
                          L"to anticheat scanners.\n";
        }
    }

    Log(opt, L"Section memory protections applied.");
    return true;
}

bool WipeHeaders(HANDLE process, std::uintptr_t remoteBase, DWORD headerSize, const Options& opt,
                 std::wstring* error) {
    /*
     * Zeroing headers removes easy PE signature scans (MZ / PE\0\0).
     *
     * DETECTION / LIMITATIONS:
     *   - Missing headers where code looks PE-like is itself suspicious
     *   - Layout can still be inferred from VAD + disassembly
     *   - Does NOT add an LDR entry — module remains "invisible" to Toolhelp
     */
    std::vector<std::uint8_t> zeros(headerSize, 0);
    if (!proc::WriteMemory(process, remoteBase, zeros.data(), zeros.size(), error)) {
        return false;
    }

    DWORD oldProt = 0;
    proc::ProtectMemory(process, reinterpret_cast<LPVOID>(remoteBase), headerSize, PAGE_NOACCESS,
                        &oldProt, nullptr);

    Log(opt, L"PE headers wiped (and marked NOACCESS).");
    return true;
}

// Allocate stub once, invoke `function(hmodule, DLL_PROCESS_ATTACH, nullptr)` remotely.
bool RemoteCall(HANDLE process, std::uintptr_t function, std::uintptr_t hmodule,
                const Options& opt, DWORD* exitCode, std::wstring* error) {
    auto stubBytes = BuildCallStubBytes();
    const std::size_t totalSize = stubBytes.size() + sizeof(CallStubData) + 16;

    LPVOID remoteStub =
        ::VirtualAllocEx(process, nullptr, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteStub) {
        if (error) {
            *error = L"VirtualAllocEx for call stub failed.";
        }
        return false;
    }

    const auto stubCodeAddr = reinterpret_cast<std::uintptr_t>(remoteStub);
    const auto stubDataAddr = stubCodeAddr + ((stubBytes.size() + 15) & ~static_cast<std::size_t>(15));

    CallStubData data{};
    data.function = function;
    data.hmodule = hmodule;

    if (!proc::WriteMemory(process, stubCodeAddr, stubBytes.data(), stubBytes.size(), error) ||
        !proc::WriteMemory(process, stubDataAddr, &data, sizeof(data), error)) {
        proc::FreeMemory(process, remoteStub, nullptr);
        return false;
    }

    DWORD oldProt = 0;
    if (!proc::ProtectMemory(process, remoteStub, stubBytes.size(), PAGE_EXECUTE_READ, &oldProt,
                             error)) {
        proc::FreeMemory(process, remoteStub, nullptr);
        return false;
    }

    LogHex(opt, L"Call stub at", stubCodeAddr);

    HANDLE thread = proc::CreateRemoteThreadSimple(process, reinterpret_cast<LPVOID>(stubCodeAddr),
                                                   reinterpret_cast<LPVOID>(stubDataAddr), error);
    if (!thread) {
        proc::FreeMemory(process, remoteStub, nullptr);
        return false;
    }

    const bool ok = proc::WaitForThread(thread, opt.threadTimeoutMs, exitCode, error);
    ::CloseHandle(thread);
    proc::FreeMemory(process, remoteStub, nullptr);
    return ok;
}

bool InvokeTlsCallbacks(HANDLE process, const pe::ImageView& image, std::uintptr_t remoteBase,
                        const Options& opt, std::wstring* error) {
    if (!opt.enableTls) {
        Log(opt, L"TLS callbacks disabled by options.");
        return true;
    }

    const auto* nt = pe::NtHeaders(image);
    const auto& tlsDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress == 0 || tlsDir.Size == 0) {
        Log(opt, L"No TLS directory.");
        return true;
    }

    /*
     * IMAGE_TLS_DIRECTORY64.AddressOfCallBacks is a VA (preferred-base absolute
     * in the file). After our remote relocations, the callback *array* in the
     * remote image holds correct remote function VAs. We read the relocated
     * array from the target and invoke each callback.
     *
     * DETECTION: TLS callbacks running from a non-LDR image before any
     * legitimate module load notification is a strong anomaly if observed.
     */
    const DWORD tlsOff = pe::RvaToFileOffset(image, tlsDir.VirtualAddress);
    const auto* tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY64*>(image.data() + tlsOff);
    if (tls->AddressOfCallBacks == 0) {
        Log(opt, L"TLS directory present but no callbacks.");
        return true;
    }

    const std::uintptr_t preferred = nt->OptionalHeader.ImageBase;
    const std::uintptr_t callbacksRemote =
        remoteBase + static_cast<std::uintptr_t>(tls->AddressOfCallBacks - preferred);

    // Read NULL-terminated callback pointers from the *remote* (relocated) image.
    for (std::uint64_t i = 0; i < 64; ++i) {
        std::uint64_t cb = 0;
        if (!proc::ReadMemory(process, callbacksRemote + i * sizeof(std::uint64_t), &cb,
                              sizeof(cb), error)) {
            return false;
        }
        if (cb == 0) {
            if (i == 0) {
                Log(opt, L"TLS callback list empty.");
            } else if (opt.verbose) {
                std::wcout << L"[*] Invoked " << i << L" TLS callback(s).\n";
            }
            return true;
        }

        if (opt.verbose) {
            std::wcout << L"[*] Invoking TLS callback at 0x" << std::hex << cb << std::dec
                       << L"\n";
        }

        DWORD exitCode = 0;
        if (!RemoteCall(process, static_cast<std::uintptr_t>(cb), remoteBase, opt, &exitCode,
                        error)) {
            return false;
        }
        (void)exitCode;  // TLS callbacks typically return void; exit code ignored.
    }

    if (error) {
        *error = L"TLS callback list unexpectedly long — aborting.";
    }
    return false;
}

bool ExecuteDllMain(HANDLE process, std::uintptr_t remoteBase, std::uintptr_t entryPoint,
                    const Options& opt, std::wstring* error) {
    /*
     * =====================================================================
     * WHY CreateRemoteThread IS DETECTABLE (and what to use instead)
     * =====================================================================
     * CreateRemoteThread / NtCreateThreadEx:
     *   - Fires PsSetCreateThreadNotifyRoutine with a start address
     *   - Start address often in MEM_PRIVATE (not a known module)
     *   - Easy usermode hook surface in the injector process
     *
     * Alternatives (still imperfect in user-mode):
     *   - QueueUserAPC / NtQueueApcThread on an alertable thread
     *   - Thread hijacking: suspend, set RIP to stub, resume
     *   - SetWindowsHookEx (needs a message loop; different tradeoffs)
     *   - Kernel APC / driver-assisted execution
     *
     * This lab tool uses CreateRemoteThread for clarity and reliability.
     */
    Log(opt, L"Creating remote thread to call DllMain(DLL_PROCESS_ATTACH)...");
    Log(opt, L"NOTE: CreateRemoteThread is one of the loudest user-mode signals.");

    DWORD exitCode = 0;
    if (!RemoteCall(process, entryPoint, remoteBase, opt, &exitCode, error)) {
        return false;
    }

    if (exitCode == 0) {
        if (error) {
            *error = L"DllMain returned FALSE (thread exit code 0).";
        }
        return false;
    }

    Log(opt, L"DllMain returned TRUE.");
    return true;
}

}  // namespace

Result ManualMap(DWORD pid, const std::wstring& dllPath, const Options& options) {
    Result result;

    std::wstring error;
    Log(options, L"Loading DLL file locally...");
    pe::ImageView image = pe::LoadFile(dllPath, &error);
    if (image.empty()) {
        result.message = error;
        LogFail(options, error);
        return result;
    }

    if (!pe::ValidatePe64Dll(image, &error)) {
        result.message = error;
        LogFail(options, error);
        return result;
    }

    const auto* nt = pe::NtHeaders(image);
    const std::uintptr_t preferredBase = static_cast<std::uintptr_t>(nt->OptionalHeader.ImageBase);
    const std::size_t imageSize = nt->OptionalHeader.SizeOfImage;
    const DWORD entryRva = nt->OptionalHeader.AddressOfEntryPoint;

    LogHex(options, L"Preferred ImageBase:", preferredBase);
    if (options.verbose) {
        std::wcout << L"[*] SizeOfImage: " << imageSize << L" bytes\n";
        std::wcout << L"[*] EntryPoint RVA: 0x" << std::hex << entryRva << std::dec << L"\n";
    }

    HANDLE process = proc::OpenTargetProcess(pid, &error);
    if (!process) {
        result.message = error;
        LogFail(options, error);
        return result;
    }

    /*
     * DETECTION at allocation:
     *   VirtualAllocEx -> MEM_PRIVATE VAD, no SectionObject / file backing.
     *   Legitimate DLLs are MEM_IMAGE with a mapped file path.
     */
    Log(options, L"Allocating remote image memory...");
    LPVOID remoteMem = proc::AllocateNearPreferred(process, preferredBase, imageSize, &error);
    if (!remoteMem) {
        result.message = error;
        LogFail(options, error);
        ::CloseHandle(process);
        return result;
    }

    const std::uintptr_t remoteBase = reinterpret_cast<std::uintptr_t>(remoteMem);
    result.remoteBase = remoteBase;
    LogHex(options, L"Remote image base:", remoteBase);

    auto fail = [&](const std::wstring& msg) -> Result {
        result.message = msg;
        LogFail(options, msg);
        proc::FreeMemory(process, remoteMem, nullptr);
        ::CloseHandle(process);
        return result;
    };

    if (!MapSections(process, image, remoteBase, options, &error)) {
        return fail(error);
    }
    if (!ApplyRelocations(process, image, remoteBase, preferredBase, options, &error)) {
        return fail(error);
    }
    if (!ResolveImports(process, pid, image, remoteBase, options, &error)) {
        return fail(error);
    }

    // TLS before final page locks / header wipe so callback pages are still RW as needed.
    // Protections are applied next; TLS code sections become RX afterward.
    // Invoke TLS after protections so we match loader-ish execute permissions.
    if (!ApplySectionProtections(process, image, remoteBase, options, &error)) {
        return fail(error);
    }
    if (!InvokeTlsCallbacks(process, image, remoteBase, options, &error)) {
        return fail(error);
    }

    if (options.wipeHeaders) {
        if (!WipeHeaders(process, remoteBase, nt->OptionalHeader.SizeOfHeaders, options, &error)) {
            return fail(error);
        }
    }

    if (entryRva == 0) {
        return fail(L"AddressOfEntryPoint is zero — nothing to execute.");
    }

    const std::uintptr_t entryPoint = remoteBase + entryRva;
    LogHex(options, L"DllMain at", entryPoint);

    if (!ExecuteDllMain(process, remoteBase, entryPoint, options, &error)) {
        result.message = error;
        LogFail(options, error);
        ::CloseHandle(process);
        return result;
    }

    ::CloseHandle(process);

    result.success = true;
    result.message = L"Manual map succeeded.";
    Log(options, L"Manual map succeeded.");
    LogHex(options, L"Mapped base address:", remoteBase);
    Log(options, L"REMINDER: module is NOT in PEB LDR lists — EnumProcessModules will miss it.");
    return result;
}

}  // namespace mapper
