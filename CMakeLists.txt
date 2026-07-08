cmake_minimum_required(VERSION 3.20)
project(injectorz
    VERSION 1.0.0
    DESCRIPTION "Educational x64 DLL manual-map injector for anticheat research"
    LANGUAGES CXX)

# ---------------------------------------------------------------------------
# Toolchain / language
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
    message(FATAL_ERROR "injectorz targets Windows x64 only.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR "injectorz requires a 64-bit toolchain (x64).")
endif()

# ---------------------------------------------------------------------------
# Injector executable
# ---------------------------------------------------------------------------
add_executable(injectorz
    src/main.cpp
    src/manual_mapper.cpp
    src/pe_utils.cpp
    src/process_utils.cpp
)

target_include_directories(injectorz PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_definitions(injectorz PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

if(MSVC)
    target_compile_options(injectorz PRIVATE
        /W4
        /permissive-
        /EHsc
        /utf-8
    )
    # Static CRT keeps the research binary self-contained on lab VMs.
    set_property(TARGET injectorz PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_link_libraries(injectorz PRIVATE
    kernel32
    user32
    advapi32
)

# ---------------------------------------------------------------------------
# Minimal test payload DLL (Win32-only, no CRT init required)
# ---------------------------------------------------------------------------
add_library(test_payload SHARED
    payload/test_payload.cpp
)

target_compile_definitions(test_payload PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
)

if(MSVC)
    target_compile_options(test_payload PRIVATE /W4 /permissive- /utf-8)
    # Avoid CRT startup that LoadLibrary would normally run for us.
    # Manual mapping does NOT call _DllMainCRTStartup — keep the payload
    # free of CRT dependencies so DllMain is safe to invoke directly.
    target_compile_options(test_payload PRIVATE /GS-)
    # CRITICAL: without /ENTRY:DllMain, AddressOfEntryPoint is
    # _DllMainCRTStartup and a manual map will crash before DllMain.
    target_link_options(test_payload PRIVATE /ENTRY:DllMain /NODEFAULTLIB)
    set_property(TARGET test_payload PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

target_link_libraries(test_payload PRIVATE
    kernel32
    user32
)

# Place both artifacts next to each other for easy lab testing.
set_target_properties(injectorz test_payload PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

message(STATUS "injectorz: configure a Visual Studio 2022 x64 generator, e.g.")
message(STATUS "  cmake -S . -B build -G \"Visual Studio 17 2022\" -A x64")
message(STATUS "  cmake --build build --config Release")
