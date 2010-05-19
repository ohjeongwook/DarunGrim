call "%ProgramFiles(x86)%\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
nmake nodebug=1
dir WIN2000_DEBUG\*.exe
copy WIN2000_DEBUG\*.exe ..\Bin\
copy WIN2000_RETAIL\*.exe ..\Bin\

copy WIN2000_RETAIL\*.pyd ..\Bin\
copy DiffEngine.py ..\Bin\

pause
