#pragma once
/*
 * process_utils.h — Target process discovery and remote memory / execution.
 *
 * Every API used here leaves a behavioral footprint. Comments throughout
 * the .cpp call out what an anticheat can observe (handles, threads, VADs).
 */

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace proc {

struct ModuleInfo {
    std::wstring name;       // e.g. L"kernel32.dll"
    std::uintptr_t base = 0;
    std::size_t size = 0;
};

[[nodiscard]] DWORD FindProcessIdByName(const std::wstring& processName, std::wstring* error);

[[nodiscard]] HANDLE OpenTargetProcess(DWORD pid, std::wstring* error);

[[nodiscard]] bool ReadMemory(HANDLE process, std::uintptr_t address, void* buffer, std::size_t size,
                              std::wstring* error);

[[nodiscard]] bool WriteMemory(HANDLE process, std::uintptr_t address, const void* buffer,
                               std::size_t size, std::wstring* error);

// Prefer ImageBase; fall back to any suitable region if preferred base is taken.
[[nodiscard]] LPVOID AllocateNearPreferred(HANDLE process, std::uintptr_t preferredBase,
                                           std::size_t size, std::wstring* error);

[[nodiscard]] bool ProtectMemory(HANDLE process, LPVOID address, std::size_t size,
                                 DWORD newProtect, DWORD* oldProtect, std::wstring* error);

[[nodiscard]] bool FreeMemory(HANDLE process, LPVOID address, std::wstring* error);

// Enumerate modules loaded in the remote process (Toolhelp32 snapshot).
[[nodiscard]] std::vector<ModuleInfo> EnumerateModules(DWORD pid, std::wstring* error);

[[nodiscard]] std::uintptr_t FindModuleBase(DWORD pid, const std::wstring& moduleName,
                                            std::wstring* error);

// Resolve an export inside a remote module by parsing its export directory
// with ReadProcessMemory (does not call GetProcAddress in the target).
[[nodiscard]] std::uintptr_t ResolveRemoteExport(HANDLE process, std::uintptr_t moduleBase,
                                                 const char* name, std::wstring* error);

[[nodiscard]] std::uintptr_t ResolveRemoteExportByOrdinal(HANDLE process, std::uintptr_t moduleBase,
                                                          WORD ordinal, std::wstring* error);

// Create a remote thread at `start` with `param`. Highly detectable — see .cpp.
[[nodiscard]] HANDLE CreateRemoteThreadSimple(HANDLE process, LPVOID start, LPVOID param,
                                              std::wstring* error);

[[nodiscard]] bool WaitForThread(HANDLE thread, DWORD timeoutMs, DWORD* exitCode,
                                 std::wstring* error);

}  // namespace proc
