#pragma once
/*
 * manual_mapper.h — Orchestrates the full x64 DLL manual-map pipeline.
 *
 * Pipeline (mirrors what the Windows loader does, minus LDR registration):
 *   1. Parse local PE
 *   2. Allocate remote image (prefer ImageBase)
 *   3. Copy headers + sections
 *   4. Apply base relocations
 *   5. Resolve imports (IAT)
 *   6. Optionally run TLS callbacks
 *   7. Apply per-section page protections
 *   8. Wipe PE headers (stealth / anti-dump)
 *   9. Call DllMain(DLL_PROCESS_ATTACH) via remote stub
 *
 * Anything missing from a normal LoadLibrary path is a detection seam.
 */

#include <Windows.h>
#include <cstdint>
#include <string>

namespace mapper {

struct Options {
    bool wipeHeaders = true;     // Zero SizeOfHeaders at remote base
    bool enableTls = true;       // Invoke TLS callbacks before DllMain
    bool verbose = true;         // Log each stage to stdout
    DWORD threadTimeoutMs = 15000;
};

struct Result {
    bool success = false;
    std::uintptr_t remoteBase = 0;
    std::wstring message;
};

// Inject `dllPath` into process `pid` using manual mapping.
[[nodiscard]] Result ManualMap(DWORD pid, const std::wstring& dllPath, const Options& options);

}  // namespace mapper
