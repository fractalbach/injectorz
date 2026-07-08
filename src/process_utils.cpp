#include "process_utils.h"

#include <TlHelp32.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>
#include <cwctype>

namespace proc {
namespace {

std::wstring ToLower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), [](wchar_t c) {
        return static_cast<wchar_t>(::towlower(c));
    });
    return s;
}

bool EqualsIgnoreCase(const std::wstring& a, const std::wstring& b) {
    return ToLower(a) == ToLower(b);
}

// Read a null-terminated ASCII string from remote memory (bounded).
bool ReadRemoteCString(HANDLE process, std::uintptr_t address, std::string& out, std::size_t maxLen,
                       std::wstring* error) {
    out.clear();
    out.reserve(64);
    for (std::size_t i = 0; i < maxLen; ++i) {
        char ch = 0;
        if (!ReadMemory(process, address + i, &ch, 1, error)) {
            return false;
        }
        if (ch == '\0') {
            return true;
        }
        out.push_back(ch);
    }
    if (error) {
        *error = L"Remote C-string exceeded max length while resolving export.";
    }
    return false;
}

}  // namespace

DWORD FindProcessIdByName(const std::wstring& processName, std::wstring* error) {
    /*
     * DETECTION: CreateToolhelp32Snapshot / Process32FirstW are common
     * reconnaissance APIs. Anticheats often monitor who enumerates game
     * processes from external handles. Prefer a known PID in lab tests when
     * you want to reduce noise.
     */
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        if (error) {
            *error = L"CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) failed.";
        }
        return 0;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    DWORD found = 0;

    if (::Process32FirstW(snap, &pe)) {
        do {
            if (EqualsIgnoreCase(pe.szExeFile, processName)) {
                found = pe.th32ProcessID;
                break;
            }
        } while (::Process32NextW(snap, &pe));
    }

    ::CloseHandle(snap);

    if (!found && error) {
        *error = L"Process not found: " + processName;
    }
    return found;
}

HANDLE OpenTargetProcess(DWORD pid, std::wstring* error) {
    /*
     * Rights requested for a full manual map:
     *   PROCESS_VM_OPERATION  — VirtualAllocEx / VirtualProtectEx / VirtualFreeEx
     *   PROCESS_VM_WRITE      — WriteProcessMemory
     *   PROCESS_VM_READ       — ReadProcessMemory (IAT / export parsing)
     *   PROCESS_CREATE_THREAD — CreateRemoteThread (DllMain bootstrap)
     *   PROCESS_QUERY_INFORMATION — basic queries
     *
     * DETECTION: Opening a game process with CREATE_THREAD | VM_* is a classic
     * red flag. Kernel ObRegisterCallbacks / minifilters can deny or log this.
     * Stealthier research paths: duplicate an existing handle, use a driver,
     * or avoid CreateRemoteThread entirely (APC / hijack).
     */
    const DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
                         PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION;

    HANDLE process = ::OpenProcess(access, FALSE, pid);
    if (!process) {
        if (error) {
            *error = L"OpenProcess failed. Run elevated or check PID. GetLastError=" +
                     std::to_wstring(::GetLastError());
        }
        return nullptr;
    }
    return process;
}

bool ReadMemory(HANDLE process, std::uintptr_t address, void* buffer, std::size_t size,
                std::wstring* error) {
    SIZE_T read = 0;
    if (!::ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), buffer, size, &read) ||
        read != size) {
        if (error) {
            *error = L"ReadProcessMemory failed at 0x" +
                     std::to_wstring(address) + L" err=" + std::to_wstring(::GetLastError());
        }
        return false;
    }
    return true;
}

bool WriteMemory(HANDLE process, std::uintptr_t address, const void* buffer, std::size_t size,
                 std::wstring* error) {
    /*
     * DETECTION: WriteProcessMemory is heavily monitored. ETW providers and
     * kernel callbacks can attribute cross-process writes. Direct syscalls
     * (NtWriteVirtualMemory) reduce usermode hook visibility but not kernel
     * telemetry.
     */
    SIZE_T written = 0;
    if (!::WriteProcessMemory(process, reinterpret_cast<LPVOID>(address), buffer, size, &written) ||
        written != size) {
        if (error) {
            *error = L"WriteProcessMemory failed at 0x" +
                     std::to_wstring(address) + L" err=" + std::to_wstring(::GetLastError());
        }
        return false;
    }
    return true;
}

LPVOID AllocateNearPreferred(HANDLE process, std::uintptr_t preferredBase, std::size_t size,
                             std::wstring* error) {
    /*
     * Allocate RW first; section protections are applied after mapping.
     * Starting RW (not RWX) avoids the most obvious "private executable
     * allocation" signature during the copy phase — though the region still
     * becomes executable later and remains file-backed-less (MEM_PRIVATE).
     *
     * DETECTION: MEM_PRIVATE + executable pages with no mapped image file
     * are a primary manual-map indicator (VAD / MmQueryVirtualMemory).
     */
    LPVOID remote = nullptr;

    if (preferredBase != 0) {
        remote = ::VirtualAllocEx(process, reinterpret_cast<LPVOID>(preferredBase), size,
                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remote) {
            return remote;
        }
        // Preferred base taken — fall through. Relocations will fix the delta.
    }

    remote = ::VirtualAllocEx(process, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!remote && error) {
        *error = L"VirtualAllocEx failed. GetLastError=" + std::to_wstring(::GetLastError());
    }
    return remote;
}

bool ProtectMemory(HANDLE process, LPVOID address, std::size_t size, DWORD newProtect,
                   DWORD* oldProtect, std::wstring* error) {
    DWORD old = 0;
    if (!::VirtualProtectEx(process, address, size, newProtect, &old)) {
        if (error) {
            *error = L"VirtualProtectEx failed. GetLastError=" + std::to_wstring(::GetLastError());
        }
        return false;
    }
    if (oldProtect) {
        *oldProtect = old;
    }
    return true;
}

bool FreeMemory(HANDLE process, LPVOID address, std::wstring* error) {
    if (!::VirtualFreeEx(process, address, 0, MEM_RELEASE)) {
        if (error) {
            *error = L"VirtualFreeEx failed. GetLastError=" + std::to_wstring(::GetLastError());
        }
        return false;
    }
    return true;
}

std::vector<ModuleInfo> EnumerateModules(DWORD pid, std::wstring* error) {
    std::vector<ModuleInfo> modules;

    /*
     * Toolhelp module snapshots walk the PEB LDR lists indirectly.
     * Manually mapped images are intentionally ABSENT from these lists —
     * that absence is itself a detection opportunity when code executes
     * from an unknown base.
     */
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        if (error) {
            *error = L"CreateToolhelp32Snapshot(TH32CS_SNAPMODULE) failed. err=" +
                     std::to_wstring(::GetLastError());
        }
        return modules;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);
    if (::Module32FirstW(snap, &me)) {
        do {
            ModuleInfo info;
            info.name = me.szModule;
            info.base = reinterpret_cast<std::uintptr_t>(me.modBaseAddr);
            info.size = static_cast<std::size_t>(me.modBaseSize);
            modules.push_back(std::move(info));
        } while (::Module32NextW(snap, &me));
    }

    ::CloseHandle(snap);
    return modules;
}

std::uintptr_t FindModuleBase(DWORD pid, const std::wstring& moduleName, std::wstring* error) {
    const auto modules = EnumerateModules(pid, error);
    for (const auto& m : modules) {
        if (EqualsIgnoreCase(m.name, moduleName)) {
            return m.base;
        }
    }
    if (error) {
        *error = L"Module not loaded in target: " + moduleName;
    }
    return 0;
}

std::uintptr_t ResolveRemoteExport(HANDLE process, std::uintptr_t moduleBase, const char* name,
                                   std::wstring* error) {
    /*
     * Parse IMAGE_EXPORT_DIRECTORY in the remote module.
     *
     * Why not GetProcAddress locally?
     *   ASLR means the same DLL may be at different bases in injector vs
     *   target. We need the address valid *inside the target*.
     *
     * DETECTION: Walking export tables via RPM is noisy but normal for
     * debuggers. The more interesting artifact is later: IAT slots in a
     * private allocation pointing at legitimate module exports.
     */
    IMAGE_DOS_HEADER dos{};
    if (!ReadMemory(process, moduleBase, &dos, sizeof(dos), error)) {
        return 0;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
        if (error) {
            *error = L"Remote module has invalid DOS signature.";
        }
        return 0;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadMemory(process, moduleBase + dos.e_lfanew, &nt, sizeof(nt), error)) {
        return 0;
    }
    if (nt.Signature != IMAGE_NT_SIGNATURE ||
        nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (error) {
            *error = L"Remote module is not a valid PE32+ image.";
        }
        return 0;
    }

    const auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir.VirtualAddress == 0 || expDir.Size == 0) {
        if (error) {
            *error = L"Remote module has no export directory.";
        }
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exports{};
    if (!ReadMemory(process, moduleBase + expDir.VirtualAddress, &exports, sizeof(exports),
                    error)) {
        return 0;
    }

    std::vector<DWORD> names(exports.NumberOfNames);
    std::vector<WORD> ordinals(exports.NumberOfNames);
    std::vector<DWORD> functions(exports.NumberOfFunctions);

    if (exports.NumberOfNames) {
        if (!ReadMemory(process, moduleBase + exports.AddressOfNames, names.data(),
                        names.size() * sizeof(DWORD), error)) {
            return 0;
        }
        if (!ReadMemory(process, moduleBase + exports.AddressOfNameOrdinals, ordinals.data(),
                        ordinals.size() * sizeof(WORD), error)) {
            return 0;
        }
    }
    if (exports.NumberOfFunctions) {
        if (!ReadMemory(process, moduleBase + exports.AddressOfFunctions, functions.data(),
                        functions.size() * sizeof(DWORD), error)) {
            return 0;
        }
    }

    for (DWORD i = 0; i < exports.NumberOfNames; ++i) {
        std::string exportName;
        if (!ReadRemoteCString(process, moduleBase + names[i], exportName, 512, error)) {
            return 0;
        }
        if (exportName == name) {
            const WORD ordIndex = ordinals[i];
            if (ordIndex >= functions.size()) {
                if (error) {
                    *error = L"Export ordinal index out of range.";
                }
                return 0;
            }
            const DWORD rva = functions[ordIndex];
            // Forwarded exports land inside the export directory RVA range.
            if (rva >= expDir.VirtualAddress && rva < expDir.VirtualAddress + expDir.Size) {
                if (error) {
                    *error = L"Forwarded exports are not resolved by this lab injector: " +
                             std::wstring(name, name + std::strlen(name));
                }
                return 0;
            }
            return moduleBase + rva;
        }
    }

    if (error) {
        *error = L"Export not found: ";
        for (const char* p = name; *p; ++p) {
            error->push_back(static_cast<wchar_t>(*p));
        }
    }
    return 0;
}

std::uintptr_t ResolveRemoteExportByOrdinal(HANDLE process, std::uintptr_t moduleBase, WORD ordinal,
                                            std::wstring* error) {
    IMAGE_DOS_HEADER dos{};
    if (!ReadMemory(process, moduleBase, &dos, sizeof(dos), error)) {
        return 0;
    }

    IMAGE_NT_HEADERS64 nt{};
    if (!ReadMemory(process, moduleBase + dos.e_lfanew, &nt, sizeof(nt), error)) {
        return 0;
    }

    const auto& expDir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!expDir.VirtualAddress) {
        if (error) {
            *error = L"Remote module has no export directory (ordinal resolve).";
        }
        return 0;
    }

    IMAGE_EXPORT_DIRECTORY exports{};
    if (!ReadMemory(process, moduleBase + expDir.VirtualAddress, &exports, sizeof(exports),
                    error)) {
        return 0;
    }

    if (ordinal < exports.Base) {
        if (error) {
            *error = L"Ordinal below export Base.";
        }
        return 0;
    }

    const DWORD index = ordinal - exports.Base;
    if (index >= exports.NumberOfFunctions) {
        if (error) {
            *error = L"Ordinal out of range.";
        }
        return 0;
    }

    DWORD rva = 0;
    if (!ReadMemory(process,
                    moduleBase + exports.AddressOfFunctions + index * sizeof(DWORD), &rva,
                    sizeof(rva), error)) {
        return 0;
    }
    if (rva == 0) {
        if (error) {
            *error = L"Ordinal maps to empty function RVA.";
        }
        return 0;
    }
    if (rva >= expDir.VirtualAddress && rva < expDir.VirtualAddress + expDir.Size) {
        if (error) {
            *error = L"Forwarded ordinal exports are not supported in this lab tool.";
        }
        return 0;
    }
    return moduleBase + rva;
}

HANDLE CreateRemoteThreadSimple(HANDLE process, LPVOID start, LPVOID param, std::wstring* error) {
    /*
     * =====================================================================
     * WHY CreateRemoteThread IS DETECTABLE (and what to use instead)
     * =====================================================================
     * CreateRemoteThread / NtCreateThreadEx:
     *   - Generates a thread-creation notification (PsSetCreateThreadNotifyRoutine)
     *   - Start address often points into MEM_PRIVATE (not a known module)
     *   - Thread start address outside any LDR module is a strong signal
     *   - Usermode hooks on CreateRemoteThread in the injector are trivial
     *
     * Alternatives (still user-mode, still imperfect):
     *   - QueueUserAPC / NtQueueApcThread to an alertable thread
     *   - Thread hijacking: suspend, set RIP to stub, resume
     *   - SetWindowsHookEx (different tradeoffs; needs a message loop)
     *   - Instrumentation callbacks / kernel APC (elevates to driver land)
     *
     * This lab tool intentionally uses CreateRemoteThread for clarity.
     */
    HANDLE thread = ::CreateRemoteThread(process, nullptr, 0,
                                         reinterpret_cast<LPTHREAD_START_ROUTINE>(start), param, 0,
                                         nullptr);
    if (!thread && error) {
        *error = L"CreateRemoteThread failed. GetLastError=" + std::to_wstring(::GetLastError());
    }
    return thread;
}

bool WaitForThread(HANDLE thread, DWORD timeoutMs, DWORD* exitCode, std::wstring* error) {
    const DWORD wait = ::WaitForSingleObject(thread, timeoutMs);
    if (wait == WAIT_TIMEOUT) {
        if (error) {
            *error = L"Remote thread wait timed out.";
        }
        return false;
    }
    if (wait != WAIT_OBJECT_0) {
        if (error) {
            *error = L"WaitForSingleObject failed on remote thread.";
        }
        return false;
    }
    if (exitCode) {
        if (!::GetExitCodeThread(thread, exitCode)) {
            if (error) {
                *error = L"GetExitCodeThread failed.";
            }
            return false;
        }
    }
    return true;
}

}  // namespace proc
