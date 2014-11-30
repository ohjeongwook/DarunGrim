set PYTHONPATH=%PYTHONPATH%;C:\mat\Src\DarunGrim\Src\UI\FlowGrapher;C:\mat\Src\DarunGrim\Src\Scripts\FileManagement
pyinstaller DarunGrim.spec
copy /Y ..\..\bin\GraphViz\* dist\DarunGrim

copy ..\..\Release\DarunGrimPlugin.plw dist\DarunGrim
copy ..\..\Release\DarunGrimC.exe dist\DarunGrim

mkdir dist\DarunGrim\DarunGrim3
xcopy ..\..\Release\* dist\DarunGrim\DarunGrim3

mkdir dist\DarunGrim\x64
xcopy ..\..\x64\Release-x64\* dist\DarunGrim\x64

copy c:\windows\syswow64\msvcr120.dll dist\DarunGrim

copy DarunGrim.png dist\DarunGrim
copy DarunGrimSplash.png dist\DarunGrim
pause