@echo off
setlocal
pushd "%~dp0"
set "NASM_EXE=nasm"
where nasm >nul 2>nul || set "NASM_EXE=C:\Program Files\NASM\nasm.exe"
if not exist "%NASM_EXE%" (echo NASM not found& popd& exit /b 1)

set "LINK_EXE=link"
where link >nul 2>nul || set "LINK_EXE=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\link.exe"
if not exist "%LINK_EXE%" (echo MSVC link.exe not found& popd& exit /b 1)

set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"
if not exist "%SDK_LIB%\Kernel32.lib" set "SDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.28000.0\um\x64"
if not exist "%SDK_LIB%\Kernel32.lib" (echo Windows SDK x64 libraries not found& popd& exit /b 1)

"%NASM_EXE%" -f win64 main.asm -o backend.obj || (popd& exit /b 1)
"%LINK_EXE%" /nologo /subsystem:console /entry:main backend.obj /libpath:"%SDK_LIB%" Ws2_32.lib Kernel32.lib Bcrypt.lib /out:ogfn-server-8080.exe || (popd& exit /b 1)
popd
echo Built ogfn-server-8080.exe
