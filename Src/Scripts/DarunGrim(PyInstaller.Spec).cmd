set PYTHONPATH=%PYTHONPATH%;C:\mat\Src\DarunGrim\Src\UI\FlowGrapher;C:\mat\Src\DarunGrim\Src\Scripts\FileManagement
pyinstaller DarunGrim.spec
copy /Y ..\..\bin\GraphViz\* dist\DarunGrim
copy /Y dist\DarunGrim\* ..\..\Release
copy ..\..\Release\DarunGrimPlugin.plw dist\DarunGrim
pause