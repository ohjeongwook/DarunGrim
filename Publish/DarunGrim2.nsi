; example1.nsi
;
; This script is perhaps one of the simplest NSIs you can make. All of the
; optional settings are left to their default settings. The installer simply 
; prompts the user asking them where to install, and drops a copy of example1.nsi
; there. 

;--------------------------------

; The name of the installer
Name "DarunGrim2"

; The file to write
OutFile "DarunGrim2Setup.exe"

; The default installation directory
InstallDir $PROGRAMFILES\DarunGrim2

; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically
InstallDirRegKey HKLM "Software\DarunGrim2" "Install_Dir"


; Request application privileges for Windows Vista
RequestExecutionLevel admin

;--------------------------------

; Pages

Page components
Page directory
Page instfiles

UninstPage uninstConfirm
UninstPage instfiles

;--------------------------------

; The stuff to install
Section "" ;No components page, name is not important
  ; Set output path to the installation directory.
  SetOutPath $INSTDIR
  ; Put file there
  File ..\bin\DarunGrim2.exe
  File ..\bin\Conf.ini
  File ..\bin\DarunGrim2C.exe
  File T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\SortExecutables\WIN2000_DEBUG\SortExecutables.exe
  File ..\bin\cdt.dll
  File ..\bin\config
  File ..\bin\graph.dll
  File ..\bin\gvc.dll
  File ..\bin\gvplugin_core.dll
  File ..\bin\gvplugin_dot_layout.dll
  File ..\bin\gvplugin_pango.dll
  File ..\bin\iconv.dll
  File ..\bin\intl.dll
  File ..\bin\libcairo-2.dll
  File ..\bin\libexpat.dll
  File ..\bin\libfontconfig-1.dll
  File ..\bin\libfreetype-6.dll
  File ..\bin\libglib-2.0-0.dll
  File ..\bin\libgmodule-2.0-0.dll
  File ..\bin\libgobject-2.0-0.dll
  File ..\bin\libpango-1.0-0.dll
  File ..\bin\libpangocairo-1.0-0.dll
  File ..\bin\libpangoft2-1.0-0.dll
  File ..\bin\libpangowin32-1.0-0.dll
  File ..\bin\libpng12.dll
  File ..\bin\libxml2.dll
  File ..\bin\ltdl.dll
  File ..\bin\pathplan.dll
  File ..\bin\zlib1.dll
  File ..\Plugin\bin\DarunGrim2.plw

  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_is1' "Inno Setup: App Path"
  
  StrCmp $0 "" skip_plugin
    DetailPrint "IDA is installed at: $0"
    SetOutPath $0\Plugins
    File ..\Plugin\bin\DarunGrim2.plw
  skip_plugin:

  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\DarunGrim2 "Install_Dir" "$INSTDIR"
  
  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim2" "DisplayName" "DarunGrim2"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim2" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim2" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim2" "NoRepair" 1

  WriteRegStr HKCR ".dgf" "" "DarunGrim2.0"
  WriteRegStr HKCR ".dgf\OpenWithList\DarunGrim2.exe" "" ""
  WriteRegStr HKCR ".dgf\OpenWithProgids" "DarunGrim2.0" ""
  WriteRegStr HKCR "Applications\DarunGrim2.exe\Shell\Open\Command" "" "$INSTDIR\DarunGrim2.exe $\"%1$\""
  WriteRegStr HKCR "DarunGrim2.0" "" "DarunGrim2.0 Data File"
  WriteRegStr HKCR "DarunGrim2.0\DefaultIcon" "" "$INSTDIR\DarunGrim2.exe"
  WriteRegStr HKCR "DarunGrim2.0\shell\Open\Command" "" "$INSTDIR\DarunGrim2.exe $\"%1$\""


  WriteUninstaller "uninstall.exe"
SectionEnd ; end the section

; Optional section (can be disabled by the user)
Section "Start Menu Shortcuts"
  CreateDirectory "$SMPROGRAMS\DarunGrim2"
  CreateShortCut "$SMPROGRAMS\DarunGrim2\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\DarunGrim2\DarunGrim2.lnk" "$INSTDIR\DarunGrim2.exe" "" "$INSTDIR\DarunGrim2.exe" 0
SectionEnd


;--------------------------------

; Uninstaller

Section "Uninstall"
  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim2"
  DeleteRegKey HKLM SOFTWARE\DarunGrim2
  ; Remove files and uninstaller
  Delete $INSTDIR\DarunGrim2.exe
  Delete $INSTDIR\Conf.ini
  Delete $INSTDIR\DarunGrim2C.exe
  Delete $INSTDIR\SortExecutables.exe
  Delete $INSTDIR\zlib2.dll
  Delete $INSTDIR\DarunGrim2.plw
  Delete $INSTDIR\uninstall.exe
  ; Remove shortcuts, if any
  Delete "$SMPROGRAMS\DarunGrim2\*.*"
  ; Remove directories used
  RMDir "$SMPROGRAMS\DarunGrim2"
  RMDir "$INSTDIR"
SectionEnd

Function MakeSureIGotGraphViz
  IfFileExists "C:\Program Files\Graphviz 2.21\" skip
  Call ConnectInternet ;Make an internet connection (if no connection available)
  StrCpy $2 "$TEMP\graphviz-2.20.3.msi"
  NSISdl::download http://www.graphviz.org/pub/graphviz/stable/windows/graphviz-2.20.3.msi $2
  Pop $0
  StrCmp $0 success success
    SetDetailsView show
    DetailPrint "download failed: $0"
    Abort
  success:
    ExecWait 'msiexec.exe /i "$2"'
    Delete $2
    Pop $0
    StrCmp $0 "" skip
  skip:
FunctionEnd

Function ConnectInternet
  Push $R0
    ClearErrors
    Dialer::AttemptConnect
    IfErrors noie3
    Pop $R0
    StrCmp $R0 "online" connected
      MessageBox MB_OK|MB_ICONSTOP "Cannot connect to the internet."
      Quit
    noie3:
    ; IE3 not installed
    MessageBox MB_OK|MB_ICONINFORMATION "Please connect to the internet now."
    connected:
  Pop $R0
FunctionEnd

