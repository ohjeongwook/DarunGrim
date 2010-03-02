call "C:\Program Files\Microsoft Visual Studio 9.0\VC\bin\vcvars32.bat"
pushd T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\UI
nmake
dir WIN2000_DEBUG\*.exe
copy WIN2000_DEBUG\*.exe ..\Bin\
copy WIN2000_DEBUG\*.exe "C:\Program Files\DarunGrim2"
pause
