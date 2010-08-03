call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
nmake
mkdir ..\..\Bin\Plugin
copy bin\*.plw ..\..\Bin\Plugin
copy bin\*.plw "%ProgramFiles%\IDA\plugins"
pause

