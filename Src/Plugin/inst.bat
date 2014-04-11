IF EXIST "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat" call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
IF EXIST "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat" call "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
set DARUNGRIM2_ROOT=..
nmake
mkdir ..\..\..\Bin\Plugin
copy bin\*.plw ..\..\..\Bin\Plugin
IF EXIST "%ProgramFiles(x86)%\IDA\plugins" copy bin\*.plw "%ProgramFiles(x86)%\IDA\plugins"
IF EXIST "%ProgramFiles%\IDA\plugins" copy bin\*.plw "%ProgramFiles%\IDA\plugins"
pause
