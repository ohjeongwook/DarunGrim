static main()
{
        Wait();
        RunPlugin( "DarunGrimPlugin", 1 );
        SetLogFile( "C:\\mat\\Src\\DarunGrim\\Src\\Scripts\\Test\\RunDarunGrimIDC.log" );
        SaveAnalysisData( "C:\\mat\\Src\\DarunGrim\\Src\\Scripts\\Test\\RunDarunGrimIDC.dgf", 0, 0 );
        Exit( 0 );
}
