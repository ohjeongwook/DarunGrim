call "%ProgramFiles%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
nmake nodebug=1
copy WIN2000_RETAIL\*.pyd ..\..\Bin\
copy WIN2000_RETAIL\*.exe ..\..\Bin\
copy Python\*.py ..\..\Bin\

nmake WIN2000_DEBUG\DarunGrim2C.exe 
copy WIN2000_DEBUG\DarunGrim2C.exe  ..\..\Bin\DarunGrim2CDebug.exe 
copy WIN2000_DEBUG\DarunGrim2C.pdb  ..\..\Bin\DarunGrim2CDebug.pdb

pause
