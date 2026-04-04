@echo off
REM build_windows.bat — Build fialka-core as .dll for Windows Desktop (C# P/Invoke)
REM
REM Prerequisites:
REM   rustup target add x86_64-pc-windows-msvc
REM   Visual Studio Build Tools with MSVC + Windows SDK
REM
REM Output: target\x86_64-pc-windows-msvc\release\fialka_core.dll

cargo build --release --target x86_64-pc-windows-msvc

echo Build complete. DLL at: target\x86_64-pc-windows-msvc\release\fialka_core.dll
