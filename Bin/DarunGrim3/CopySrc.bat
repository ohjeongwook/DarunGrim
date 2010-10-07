REM Start copying files
mkdir Src
copy ..\..\Src\UI\Web\*.py Src\
copy ..\..\Src\UI\Web\*.bat Src\
xcopy /y /s /I ..\..\Src\UI\Web\data Src\data
copy "..\..\Src\Bin Collector\*.py" Src\
copy "..\..\Src\Diff Inspector\*.py" Src\
copy "..\..\Src\Bin Collector\Bin\*.pyd" Src\
copy SetupDist.py Src\
copy ..\..\Src\UI\Web\DarunGrim3Sample01.cfg Src\DarunGrim3.cfg
