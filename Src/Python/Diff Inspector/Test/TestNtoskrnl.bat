pushd ..\Bin
del "ntoskrnl.exe-5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)-5.1.2600.3427 (xpsp_sp2_gdr.080814-1233).dgf"
DarunGrim2C.exe -f "T:\mat\Projects\Binaries\Windows XP\Microsoft Corporation\ntoskrnl.exe\5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)\ntoskrnl.exe" "T:\mat\Projects\Binaries\Windows XP\Microsoft Corporation\ntoskrnl.exe\5.1.2600.3427 (xpsp_sp2_gdr.080814-1233)\ntoskrnl.exe" "ntoskrnl.exe-5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)-5.1.2600.3427 (xpsp_sp2_gdr.080814-1233).dgf" > log.txt
popd
GetStatistics.py "..\bin\ntoskrnl.exe-5.1.2600.2180 (xpsp_sp2_rtm.040803-2158)-5.1.2600.3427 (xpsp_sp2_gdr.080814-1233).dgf" > out2.txt
pause