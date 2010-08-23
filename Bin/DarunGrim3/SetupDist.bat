REM Clean Up
rmdir /Q /S Src
rmdir /Q /S Bin
del /Q DarunGrim3.zip

REM Start copying files
mkdir Src
copy ..\..\Src\UI\Web\*.py Src\
copy ..\..\Src\UI\Web\*.bat Src\
xcopy /y /s /I ..\..\Src\UI\Web\data Src\data
copy "..\..\Src\Bin Collector\*.py" Src\
copy "..\..\Src\Diff Inspector\*.py" Src\
copy "..\..\Src\Bin Collector\Bin\*.pyd" Src\
copy SetupDist.py Src
copy ..\..\Src\UI\Web\DarunGrim3Sample01.cfg Src\DarunGrim3.cfg

REM Generate binaries
pushd Src
c:\python26\python SetupDist.py py2exe
popd

REM Copy necessary files
copy ..\..\Src\UI\Web\DarunGrim3Sample01.cfg Src\bin\DarunGrim3.cfg
copy ..\DarunGrim2\* Src\bin
copy ..\..\Publish\Docs\*.pdf Src\bin

REM Clean up some unncessary files
del /Q Src\Bin\w9xpopen.exe
del /Q Src\Bin\Test.exe
del /Q Src\Bin\tcl*.dll
del /Q Src\Bin\tk*.dll
rmdir /Q /S Src\Bin\tcl

REM Put data directory to binary directory
xcopy /y /s /I ..\..\Src\UI\Web\data Src\bin\data

REM move bin directory location
mv Src\bin Bin

REM zip a package
zip DarunGrim3.zip Bin\*
pause
