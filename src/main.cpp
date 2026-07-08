/*
 * main.cpp — CLI for the educational x64 DLL manual-map injector.
 *
 * Usage examples:
 *   injectorz.exe --pid 1234 --dll test_payload.dll
 *   injectorz.exe --process-name notepad.exe --dll test_payload.dll
 *   injectorz.exe --pid 1234 --dll test_payload.dll --no-wipe --no-tls --quiet
 */

#include "manual_mapper.h"
#include "process_utils.h"

#include <Windows.h>

#include <iostream>
#include <string>

namespace {

void PrintUsage(const wchar_t* argv0) {
    std::wcerr
        << L"injectorz — educational x64 DLL manual-map injector (anticheat research)\n\n"
        << L"Usage:\n"
        << L"  " << argv0 << L" --pid <pid> --dll <path> [options]\n"
        << L"  " << argv0 << L" --process-name <exe> --dll <path> [options]\n\n"
        << L"Required:\n"
        << L"  --dll <path>              Path to the x64 DLL to manual-map\n"
        << L"  --pid <pid>               Target process ID\n"
        << L"  --process-name <exe>      Target process executable name (e.g. notepad.exe)\n\n"
        << L"Options:\n"
        << L"  --no-wipe                 Do not erase PE headers after mapping\n"
        << L"  --no-tls                  Do not invoke TLS callbacks\n"
        << L"  --quiet                   Reduce logging\n"
        << L"  --timeout <ms>            Remote thread wait timeout (default 15000)\n"
        << L"  --help                    Show this help\n\n"
        << L"DISCLAIMER: Use only against software you own / are authorized to test.\n";
}

std::wstring GetArg(int argc, wchar_t** argv, int& i) {
    if (i + 1 >= argc) {
        return {};
    }
    ++i;
    return argv[i];
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
    // Ensure wide console output works on typical lab VMs.
    ::SetConsoleOutputCP(CP_UTF8);

    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }

    DWORD pid = 0;
    std::wstring processName;
    std::wstring dllPath;
    mapper::Options options;

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h" || arg == L"/?") {
            PrintUsage(argv[0]);
            return 0;
        }
        if (arg == L"--pid") {
            const std::wstring v = GetArg(argc, argv, i);
            if (v.empty()) {
                std::wcerr << L"[!] --pid requires a value\n";
                return 1;
            }
            pid = static_cast<DWORD>(std::wcstoul(v.c_str(), nullptr, 10));
        } else if (arg == L"--process-name") {
            processName = GetArg(argc, argv, i);
            if (processName.empty()) {
                std::wcerr << L"[!] --process-name requires a value\n";
                return 1;
            }
        } else if (arg == L"--dll") {
            dllPath = GetArg(argc, argv, i);
            if (dllPath.empty()) {
                std::wcerr << L"[!] --dll requires a value\n";
                return 1;
            }
        } else if (arg == L"--no-wipe") {
            options.wipeHeaders = false;
        } else if (arg == L"--no-tls") {
            options.enableTls = false;
        } else if (arg == L"--quiet") {
            options.verbose = false;
        } else if (arg == L"--timeout") {
            const std::wstring v = GetArg(argc, argv, i);
            if (v.empty()) {
                std::wcerr << L"[!] --timeout requires a value\n";
                return 1;
            }
            options.threadTimeoutMs = static_cast<DWORD>(std::wcstoul(v.c_str(), nullptr, 10));
        } else {
            std::wcerr << L"[!] Unknown argument: " << arg << L"\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    if (dllPath.empty()) {
        std::wcerr << L"[!] --dll is required\n";
        PrintUsage(argv[0]);
        return 1;
    }
    if (pid == 0 && processName.empty()) {
        std::wcerr << L"[!] Provide --pid or --process-name\n";
        PrintUsage(argv[0]);
        return 1;
    }
    if (pid != 0 && !processName.empty()) {
        std::wcerr << L"[!] Provide only one of --pid or --process-name\n";
        return 1;
    }

    if (!processName.empty()) {
        std::wstring err;
        pid = proc::FindProcessIdByName(processName, &err);
        if (!pid) {
            std::wcerr << L"[!] " << err << L"\n";
            return 1;
        }
        if (options.verbose) {
            std::wcout << L"[*] Resolved " << processName << L" -> PID " << pid << L"\n";
        }
    }

    if (options.verbose) {
        std::wcout << L"[*] Target PID: " << pid << L"\n";
        std::wcout << L"[*] DLL: " << dllPath << L"\n";
        std::wcout << L"[*] Wipe headers: " << (options.wipeHeaders ? L"yes" : L"no") << L"\n";
        std::wcout << L"[*] TLS callbacks: " << (options.enableTls ? L"yes" : L"no") << L"\n";
    }

    const mapper::Result result = mapper::ManualMap(pid, dllPath, options);
    if (!result.success) {
        std::wcerr << L"[!] Injection failed: " << result.message << L"\n";
        if (result.remoteBase) {
            std::wcerr << L"[!] Partial remote base was 0x" << std::hex << result.remoteBase
                       << std::dec << L"\n";
        }
        return 2;
    }

    std::wcout << L"[+] SUCCESS\n";
    std::wcout << L"[+] Mapped base address: 0x" << std::hex << result.remoteBase << std::dec
               << L"\n";
    return 0;
}
