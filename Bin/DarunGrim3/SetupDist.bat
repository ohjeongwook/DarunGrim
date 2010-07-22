c:\python26\python SetupDist.py py2exe

copy DarunGrim3.cfg bin
mkdir ..\..\Publish\DarunGrim3\Bin
move bin\* ..\..\Publish\DarunGrim3\Bin
mkdir ..\..\Publish\DarunGrim3\Bin\Plugin
copy ..\Plugin\* ..\..\Publish\DarunGrim3\Bin\Plugin
copy ..\DarunGrim2\* ..\..\Publish\DarunGrim3\Bin
xcopy /S /I data ..\..\Publish\DarunGrim3\Bin\Data
pause
