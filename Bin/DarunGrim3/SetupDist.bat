c:\python26\python SetupDist.py py2exe
move bin\WebServer.exe bin\DarunGrim3Web.exe
copy DarunGrim3.cfg bin
mkdir ..\DarunGrim3.Bin
move bin\* ..\DarunGrim3.Bin
mkdir ..\DarunGrim3.Bin\Plugin
copy ..\Plugin\* ..\DarunGrim3.Bin\Plugin
copy ..\DarunGrim2\* ..\DarunGrim3.Bin
xcopy /S /I data ..\DarunGrim3.Bin\data
pause
