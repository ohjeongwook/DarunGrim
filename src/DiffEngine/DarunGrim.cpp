#include "DarunGrim.h"
#include "LogOperation.h"

LogOperation Logger;

DarunGrim::DarunGrim()
{
}

DarunGrim::~DarunGrim()
{
	_CrtDumpMemoryLeaks();
}

void DarunGrim::SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile )
{
	Logger.SetLogOutputType( ParamLogOutputType );
	if( LogFile )
		Logger.SetLogFilename( LogFile );
	Logger.SetDebugLevel( ParamDebugLevel );
}

void DarunGrim::SetIDAPath( const char *path )
{
	if( path )
		aIDAClientManager.SetIDAPath( path );
}

void DarunGrim::RunIDAToGenerateDB( char *StorageFilename, 
	char *LogFilename, 
	char *TheSourceFilename, DWORD StartAddressForSource, DWORD EndAddressForSource, 
	char *TheTargetFilename, DWORD StartAddressForTarget, DWORD EndAddressForTarget )
{

	printf("TheSourceFilename=%s\nTheTargetFilename=%s\nStorageFilename=%s\n",
		TheSourceFilename,TheTargetFilename,StorageFilename);

	aIDAClientManager.SetOutputFilename(StorageFilename);
	aIDAClientManager.SetLogFilename(LogFilename);
	aIDAClientManager.RunIDAToGenerateDB(TheSourceFilename,StartAddressForSource,EndAddressForSource);
	aIDAClientManager.RunIDAToGenerateDB(TheTargetFilename,StartAddressForTarget,EndAddressForTarget);
}
