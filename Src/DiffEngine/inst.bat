IF EXIST "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat" call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
IF EXIST "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat" call "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
set DARUNGRIM2_ROOT=..
nmake nodebug=1
copy WIN2000_RETAIL\*.pyd ..\..\..\Bin\DarunGrim2
copy WIN2000_RETAIL\*.exe ..\..\..\Bin\DarunGrim2
copy Python\*.py ..\..\..\Bin\DarunGrim2

nmake WIN2000_DEBUG\DarunGrim2C.exe 
copy WIN2000_DEBUG\DarunGrim2C.exe  ..\..\..\Bin\DarunGrim2\DarunGrim2CDebug.exe 
copy WIN2000_DEBUG\DarunGrim2C.pdb  ..\..\..\Bin\DarunGrim2\DarunGrim2CDebug.pdb

pause
