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

bool DarunGrim::RunIDAToGenerateDB( char *ParamStorageFilename, 
	char *LogFilename, 
	char *TheSourceFilename, DWORD StartAddressForSource, DWORD EndAddressForSource, 
	char *TheTargetFilename, DWORD StartAddressForTarget, DWORD EndAddressForTarget )
{
	StorageFilename = ParamStorageFilename;

	printf("TheSourceFilename=%s\nTheTargetFilename=%s\nStorageFilename=%s\n",
		TheSourceFilename,TheTargetFilename,StorageFilename);

	aIDAClientManager.SetOutputFilename(StorageFilename);
	aIDAClientManager.SetLogFilename(LogFilename);
	aIDAClientManager.RunIDAToGenerateDB(TheSourceFilename,StartAddressForSource,EndAddressForSource);
	aIDAClientManager.RunIDAToGenerateDB(TheTargetFilename,StartAddressForTarget,EndAddressForTarget);
	return OpenDatabase();
}

bool DarunGrim::OpenDatabase()
{
	pStorageDB = new DBWrapper( StorageFilename );

	pStorageDB->ExecuteStatement(NULL,NULL,CREATE_ONE_LOCATION_INFO_TABLE_STATEMENT);
	pStorageDB->ExecuteStatement(NULL,NULL,CREATE_ONE_LOCATION_INFO_TABLE_START_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL,NULL,CREATE_ONE_LOCATION_INFO_TABLE_END_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL,NULL,CREATE_MAP_INFO_TABLE_STATEMENT);
	pStorageDB->ExecuteStatement(NULL,NULL,CREATE_MAP_INFO_TABLE_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL,NULL,CREATE_FILE_INFO_TABLE_STATEMENT);
	return TRUE;
}

bool DarunGrim::Analyze()
{
	int TheSourceFileID=1;
	int TheTargetFileID=2;

	pDiffMachine=new DiffMachine();
	pDiffMachine->Retrieve( *pStorageDB,TRUE,TheSourceFileID,TheTargetFileID);
	pDiffMachine->Analyze();
	pDiffMachine->Save( *pStorageDB );
	return TRUE;
}

