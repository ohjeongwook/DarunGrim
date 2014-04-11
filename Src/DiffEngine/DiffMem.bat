set _NT_SYMBOL_PATH T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\DiffEngine\WIN2000_DEBUG
"C:\Program Files (x86)\Debugging Tools for Windows (x86)\umdh.exe" -pn:DarunGrim2CDebug.exe -f:01.log
pause
"C:\Program Files (x86)\Debugging Tools for Windows (x86)\umdh.exe" -pn:DarunGrim2CDebug.exe -f:02.log
"C:\Program Files (x86)\Debugging Tools for Windows (x86)\umdh.exe" -d 01.log 02.log > DiffMem.log
notepad DiffMem.log
del 01.log
del 02.log
