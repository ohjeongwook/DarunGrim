call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
nmake
copy bin\*.plw ..\..\Bin\
copy bin\*.plw "C:\Program Files\IDA\plugins"
pause
