IF EXIST "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat" call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
IF EXIST "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat" call "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
nmake
rem > err.txt
rem notepad err.txt
dir WIN2000_DEBUG\*.exe
copy WIN2000_DEBUG\*.exe ..\..\Bin\
copy WIN2000_DEBUG\*.exe "C:\Program Files\DarunGrim2"
pause
