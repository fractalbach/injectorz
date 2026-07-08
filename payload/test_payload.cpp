/*
 * test_payload.cpp — Minimal x64 DLL for validating the manual mapper.
 *
 * IMPORTANT FOR MANUAL MAPPING:
 *   The Windows loader normally runs CRT initialization (_DllMainCRTStartup)
 *   before your DllMain. A manual mapper typically jumps straight to the PE
 *   AddressOfEntryPoint. This payload is linked with /ENTRY:DllMain and
 *   /NODEFAULTLIB so AddressOfEntryPoint IS DllMain (no CRT).
 *
 *   Keep this file free of CRT-dependent features: no iostream, no malloc/new,
 *   no static C++ objects with dynamic constructors.
 *
 * Visible success signal:
 *   AllocConsole + WriteConsoleW, plus a MessageBox.
 *
 * Anticheat note:
 *   AllocConsole / MessageBox are extremely loud in a game process.
 *   Real malware would never do this — this is intentionally obvious for lab
 *   confirmation that DllMain ran inside the target.
 */

#include <Windows.h>

extern "C" BOOL WINAPI DllMain(HINSTANCE hModule, DWORD reason, LPVOID reserved) {
    (void)reserved;

    if (reason == DLL_PROCESS_ATTACH) {
        ::DisableThreadLibraryCalls(hModule);

        if (::AllocConsole()) {
            HANDLE out = ::GetStdHandle(STD_OUTPUT_HANDLE);
            if (out != nullptr && out != INVALID_HANDLE_VALUE) {
                wchar_t line[256];
                const int n = ::wsprintfW(
                    line,
                    L"[test_payload] Manual map SUCCESS\r\n"
                    L"[test_payload] HMODULE / base = 0x%p\r\n"
                    L"[test_payload] If you see this, DllMain ran in the target.\r\n",
                    hModule);
                if (n > 0) {
                    DWORD written = 0;
                    ::WriteConsoleW(out, line, static_cast<DWORD>(n), &written, nullptr);
                }
            }
        }

        wchar_t msg[128];
        ::wsprintfW(msg, L"test_payload mapped at 0x%p", hModule);
        ::MessageBoxW(nullptr, msg, L"injectorz test_payload", MB_OK | MB_ICONINFORMATION);
    }

    return TRUE;
}
