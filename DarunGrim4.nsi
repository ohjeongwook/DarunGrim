; example1.nsi
;
; This script is perhaps one of the simplest NSIs you can make. All of the
; optional settings are left to their default settings. The installer simply 
; prompts the user asking them where to install, and drops a copy of example1.nsi
; there. 

;--------------------------------

; The name of the installer
Name "DarunGrim4"

; The file to write
OutFile "DarunGrim4Setup.exe"

; The default installation directory
InstallDir $PROGRAMFILES\DarunGrim4

; Registry key to check for directory (so if you install again, it will 
; overwrite the old one automatically
InstallDirRegKey HKLM "Software\DarunGrim4" "Install_Dir"


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
  File Release\DarunGrim.exe
  File Release\DarunGrimC.exe
  File Release\DiffEngine.dll
  File Release\_DiffEngine.pyd
  File Release\DarunGrimPlugin.plw
  File Release\config
  File Release\Conf.ini
  File Release\cdt.dll
  File Release\DiffEngine.dll
  File Release\graph.dll
  File Release\gvc.dll
  File Release\gvplugin_core.dll
  File Release\gvplugin_dot_layout.dll
  File Release\gvplugin_pango.dll
  File Release\iconv.dll
  File Release\intl.dll
  File Release\libcairo-2.dll
  File Release\libexpat.dll
  File Release\libfontconfig-1.dll
  File Release\libfreetype-6.dll
  File Release\libglib-2.0-0.dll
  File Release\libgmodule-2.0-0.dll
  File Release\libgobject-2.0-0.dll
  File Release\libpango-1.0-0.dll
  File Release\libpangocairo-1.0-0.dll
  File Release\libpangoft2-1.0-0.dll
  File Release\libpangowin32-1.0-0.dll
  File Release\libpng12.dll
  File Release\libxml2.dll
  File Release\ltdl.dll
  File Release\pathplan.dll
  File Release\zlib1.dll
  File Src\Scripts\DarunGrim.py
  File Src\Scripts\DarunGrimDatabase.py
  File Src\Scripts\DiffEngine.py
  File Src\Scripts\SecurityImplications.py

  SetOutPath $INSTDIR\x64
  File x64\Release-x64\DarunGrimC.exe

  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_6.9_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_6.8_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_6.7_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_6.6_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_6.5_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_6.4_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro Free_is1' "Inno Setup: App Path"
  StrCmp $0 "" 0 read_ida_path
  ReadRegStr $0 HKLM 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IDA Pro_is1' "Inno Setup: App Path"
  
  read_ida_path:
  StrCmp $0 "" skip_plugin
    DetailPrint "IDA is installed at: $0"
    SetOutPath $0\Plugins
    File Release\DarunGrimPlugin.plw
  skip_plugin:

  ; Write the installation path into the registry
  WriteRegStr HKLM SOFTWARE\DarunGrim "Install_Dir" "$INSTDIR"
  
  ; Write the uninstall keys for Windows
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim" "DisplayName" "DarunGrim4"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim" "NoModify" 1
  WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim" "NoRepair" 1

  WriteRegStr HKCR ".dgf" "" "DarunGrim4.0"
  WriteRegStr HKCR ".dgf\OpenWithList\DarunGrim.exe" "" ""
  WriteRegStr HKCR ".dgf\OpenWithProgids" "DarunGrim4.0" ""
  WriteRegStr HKCR "Applications\DarunGrim.exe\Shell\Open\Command" "" "$INSTDIR\DarunGrim.exe $\"%1$\""
  WriteRegStr HKCR "DarunGrim4.0" "" "DarunGrim4.0 Data File"
  WriteRegStr HKCR "DarunGrim4.0\DefaultIcon" "" "$INSTDIR\DarunGrim.exe"
  WriteRegStr HKCR "DarunGrim4.0\shell\Open\Command" "" "$INSTDIR\DarunGrim.exe $\"%1$\""


  WriteUninstaller "uninstall.exe"
SectionEnd ; end the section

; Optional section (can be disabled by the user)
Section "Start Menu Shortcuts"
  CreateDirectory "$SMPROGRAMS\DarunGrim4"
  CreateShortCut "$SMPROGRAMS\DarunGrim4\Uninstall.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
  CreateShortCut "$SMPROGRAMS\DarunGrim4\DarunGrim.lnk" "$INSTDIR\DarunGrim.exe" "" "$INSTDIR\DarunGrim.exe" 0
SectionEnd


;--------------------------------

; Uninstaller

Section "Uninstall"
  ; Remove registry keys
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\DarunGrim"
  DeleteRegKey HKLM SOFTWARE\DarunGrim4
  ; Remove files and uninstaller
  Delete $INSTDIR\DarunGrim.exe
  Delete $INSTDIR\Conf.ini
  Delete $INSTDIR\DarunGrimC.exe
  Delete $INSTDIR\SortExecutables.exe
  Delete $INSTDIR\zlib2.dll
  Delete $INSTDIR\DarunGrimPlugin.plw
  Delete $INSTDIR\uninstall.exe
  ; Remove shortcuts, if any
  Delete "$SMPROGRAMS\DarunGrim4\*.*"
  ; Remove directories used
  RMDir "$SMPROGRAMS\DarunGrim4"
  RMDir "$INSTDIR"
SectionEnd

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

