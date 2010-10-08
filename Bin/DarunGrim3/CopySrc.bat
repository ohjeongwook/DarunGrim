REM Start copying files
mkdir Src

xcopy /D /S /I /Y ..\..\Src\UI\Web\*.py Src\
xcopy /D /S /I /Y ..\..\Src\UI\Web\*.bat Src\
xcopy /D /S /I /Y ..\..\Src\UI\Web\data Src\data
xcopy /D /S /I /Y "..\..\Src\Bin Collector\*.py" Src\
xcopy /D /S /I /Y "..\..\Src\Diff Inspector\*.py" Src\
xcopy /D /S /I /Y "..\..\Src\Bin Collector\Bin\*.pyd" Src\
xcopy /D /S /I /Y SetupDist.py Src\
copy ..\..\Src\UI\Web\DarunGrim3Sample01.cfg Src\DarunGrim3.cfg
