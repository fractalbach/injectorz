@echo off
REM build.bat — configure & build injectorz (x64 Release) with VS + CMake
setlocal EnableExtensions

where cmake >nul 2>&1
if errorlevel 1 (
  REM Prefer CMake bundled with Visual Studio
  for %%E in (Community Professional Enterprise BuildTools) do (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
      set "PATH=%ProgramFiles%\Microsoft Visual Studio\2022\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"
    )
    if exist "%ProgramFiles%\Microsoft Visual Studio\18\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" (
      set "PATH=%ProgramFiles%\Microsoft Visual Studio\18\%%E\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin;%PATH%"
    )
  )
)

where cmake >nul 2>&1
if errorlevel 1 (
  echo [!] cmake not found. Install CMake or Visual Studio C++ CMake tools.
  exit /b 1
)

cmake -S "%~dp0." -B "%~dp0build" -G "Visual Studio 17 2022" -A x64
if errorlevel 1 (
  echo [*] Trying Visual Studio 18 generator...
  cmake -S "%~dp0." -B "%~dp0build" -G "Visual Studio 18 2026" -A x64
  if errorlevel 1 (
    echo [*] Retrying with default generator -A x64 ...
    cmake -S "%~dp0." -B "%~dp0build" -A x64
    if errorlevel 1 exit /b 1
  )
)

cmake --build "%~dp0build" --config Release
if errorlevel 1 exit /b 1

echo.
echo [+] Build OK
echo     %~dp0build\bin\Release\injectorz.exe
echo     %~dp0build\bin\Release\test_payload.dll
exit /b 0
