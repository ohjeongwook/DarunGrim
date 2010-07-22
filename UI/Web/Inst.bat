mkdir ..\..\Bin\DarunGrim3
copy *.py ..\..\Bin\DarunGrim3
copy "DarunGrim3Sample01.cfg"  ..\..\Bin\DarunGrim3\DarunGrim3.cfg
xcopy /s /I data ..\..\Bin\DarunGrim3\data
copy "..\..\Bin Collector\*.py" ..\..\Bin\DarunGrim3
copy "..\..\Diff Inspector\*.py" ..\..\Bin\DarunGrim3
copy "..\..\Bin Collector\Bin\*.pyd" ..\..\Bin\DarunGrim3
xcopy /s /I ..\..\Bin\DarunGrim3 ..\..\Bin\DarunGrim3.Test
