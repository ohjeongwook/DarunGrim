set PYTHONPATH=%PYTHONPATH%;C:\mat\Src\DarunGrim\Src\UI\FlowGrapher;C:\mat\Src\DarunGrim\Src\Scripts\FileManagement

rmdir /Q /S dist\DarunGrim

pyinstaller DarunGrim.spec
copy /Y ..\..\bin\GraphViz\* dist\DarunGrim

copy ..\..\Release\DarunGrimPlugin.plw dist\DarunGrim
copy ..\..\ReleaseP64\DarunGrimPlugin.p64 dist\DarunGrim
copy ..\..\Release\DarunGrimC.exe dist\DarunGrim

mkdir dist\DarunGrim\DarunGrim3
xcopy ..\..\Release\* dist\DarunGrim\DarunGrim3
copy /Y ..\..\bin\GraphViz\* dist\DarunGrim\DarunGrim3

mkdir dist\DarunGrim\x64
xcopy ..\..\x64\Release-x64\* dist\DarunGrim\x64

copy c:\windows\syswow64\msvcr120.dll dist\DarunGrim

copy DarunGrim.png dist\DarunGrim
copy DarunGrimSplash.png dist\DarunGrim

pushd dist
zip.exe DarunGrim.zip -r -9 -xi DarunGrim\*

copy /Y DarunGrim.zip C:\Users\User\Dropbox\Public\
popd

pause