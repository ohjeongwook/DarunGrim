call "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
REM nmake nodebug=1 WIN2000_RETAIL\_DiffEngine.pyd
copy WIN2000_RETAIL\*.pyd ..\..\Bin\
copy Python\DiffEngine.py ..\..\Bin\

nmake WIN2000_DEBUG\DarunGrim2C.exe
copy WIN2000_DEBUG\*.exe ..\..\Bin\

pause
