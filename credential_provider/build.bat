@echo off
:: TAALA-2KEN Credential Provider builder script.
:: Run this from Visual Studio Developer Command Prompt.

echo =======================================================
echo TAALA-2KEN: Compiling C++ Credential Provider
echo =======================================================

if not exist build mkdir build
cd build

echo Running CMake...
cmake -G "Visual Studio 17 2022" -A x64 ..
if %ERRORLEVEL% neq 0 (
    echo CMake generation failed. Make sure Visual Studio and Build Tools are installed.
    exit /b %ERRORLEVEL%
)

echo Building DLL in Release configuration...
cmake --build . --config Release
if %ERRORLEVEL% neq 0 (
    echo Compilation failed. See compiler output errors above.
    exit /b %ERRORLEVEL%
)

echo.
echo =======================================================
echo ✓ Compilation complete! DLL generated at:
echo   credential_provider\build\bin\Release\Taala2KenCredentialProvider.dll
echo =======================================================
cd ..
