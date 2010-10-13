REM Clean Up
rmdir /Q /S Src
rmdir /Q /S Bin
del /Q DarunGrim3.zip

mkdir Src\bin
copy ..\DarunGrim2\* Src\bin\
copy ..\..\Publish\Docs\*.pdf Src\bin

call CopySrc.bat

del Src\*.pyc
REM Generate binaries
cp SetupDist.py Src
pushd Src
c:\python26\python SetupDist.py py2exe
popd

REM Prepare binary directory
REM Copy necessary files
copy ..\..\Src\UI\Web\DarunGrim3Sample01.cfg Src\bin\DarunGrim3.cfg


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
pushd Bin
zip -r ..\DarunGrim3.zip *
pause
