set PYTHONPATH=%PYTHONPATH%;C:\mat\Src\DarunGrim\Src\UI\FlowGrapher;C:\mat\Src\DarunGrim\Src\Scripts\FileManagement
pyinstaller DarunGrim.spec
copy /Y C:\mat\Src\DarunGrim\bin\GraphViz\* C:\mat\Src\DarunGrim\Src\Scripts\dist\DarunGrim
pause