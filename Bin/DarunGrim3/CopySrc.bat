REM Start copying files
mkdir Src

xcopy /D /S /I /Y ..\..\Src\UI\Web\*.py Src\
xcopy /D /S /I /Y ..\..\Src\UI\Web\*.bat Src\
xcopy /D /S /I /Y ..\..\Src\UI\Web\data Src\data
xcopy /D /S /I /Y "..\..\Src\Bin Collector\*.py" Src\
xcopy /D /S /I /Y "..\..\Src\Diff Inspector\*.py" Src\
xcopy /D /S /I /Y "..\..\Src\Bin Collector\build\lib.win32-2.6\*.pyd" Src\
xcopy /D /S /I /Y "..\..\Src\DarunGrim2\DiffEngine\WIN2000_RETAIL\*.pyd" Src\
xcopy /D /S /I /Y "..\..\Src\DarunGrim2\DiffEngine\Python\*.py" Src\
xcopy /D /S /I /Y "..\..\Src\DarunGrim2\DiffEngine\Python\*.i" Src\
xcopy /D /S /I /Y "..\Plugin" Src\Plugin\
copy ..\..\Src\UI\Web\DarunGrim3Sample01.cfg Src\DarunGrim3.cfg
