

PLUGIN
   init
   term
   run
      SaveIDAAnalysis
         SQLiteStorage
         IDAAnalyzer
            Analyze

      ConnectToDarunGrim
         ProcessCommandFromDarunGrim

      *_callback - UI interactions



LIBS:
   kernel32.lib;user32.lib;gdi32.lib;winspool.lib;comdlg32.lib;advapi32.lib;shell32.lib;ole32.lib;oleaut32.lib;uuid.lib;odbc32.lib;odbccp32.lib;ws2_32.lib;advapi32.lib;Version.lib;ida.lib;legacy_stdio_definitions.lib;%(AdditionalDependencies)


IDAAnalyzer
   only used from IDAPlugin