call "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
REM C:\Program Files (x86)\IDA\plugins
nmake
copy bin\*.plw ..\..\Bin\
copy bin\*.plw "%ProgramFiles(x86)%\IDA\plugins"
pause
