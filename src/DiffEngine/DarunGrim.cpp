#include "Common.h"
#include "DarunGrim.h"
#include "LogOperation.h"

LogOperation Logger;

DarunGrim::DarunGrim(): 
	pStorageDB(NULL),
	pOneIDAClientManagerTheSource(NULL),
	pOneIDAClientManagerTheTarget(NULL),
	pDiffMachine(NULL),
	pIDAClientManager(NULL)
{
	Logger.SetLogOutputType( LogToStdout );
	Logger.SetDebugLevel( 0 );
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	pIDAClientManager = new IDAClientManager();
}

DarunGrim::~DarunGrim()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	if( pStorageDB )
	{
		pStorageDB->CloseDatabase();
		delete pStorageDB;
	}

	if( pDiffMachine )
		delete pDiffMachine;

	if( pIDAClientManager )
		delete pIDAClientManager;

	if( pOneIDAClientManagerTheSource )
		delete pOneIDAClientManagerTheSource;

	if( pOneIDAClientManagerTheTarget )
		delete pOneIDAClientManagerTheTarget;
}

void DarunGrim::SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	Logger.SetLogOutputType( ParamLogOutputType );
	if( LogFile )
		Logger.SetLogFilename( LogFile );
	Logger.SetDebugLevel( ParamDebugLevel );
}

void DarunGrim::SetIDAPath( const char *path )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	if( path )
		pIDAClientManager->SetIDAPath( path );
}

bool DarunGrim::GenerateDB( 
	char *ParamStorageFilename, 
	char *LogFilename, 
	char *TheSourceFilename, DWORD StartAddressForSource, DWORD EndAddressForSource, 
	char *TheTargetFilename, DWORD StartAddressForTarget, DWORD EndAddressForTarget )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	StorageFilename = ParamStorageFilename;

	printf("TheSourceFilename=%s\nTheTargetFilename=%s\nStorageFilename=%s\n",
		TheSourceFilename,TheTargetFilename,StorageFilename);

	pIDAClientManager->SetOutputFilename(StorageFilename);
	pIDAClientManager->SetLogFilename(LogFilename);
	pIDAClientManager->RunIDAToGenerateDB(TheSourceFilename,StartAddressForSource,EndAddressForSource);
	pIDAClientManager->RunIDAToGenerateDB(TheTargetFilename,StartAddressForTarget,EndAddressForTarget);
	return OpenDatabase();
}

bool DarunGrim::AcceptIDAClientsFromSocket( const char *storage_filename )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	if( storage_filename )
	{
		if( pStorageDB )
			delete pStorageDB;

		pStorageDB = new DBWrapper( (char *) storage_filename );
	}

	if( pStorageDB )
	{
		pIDAClientManager->SetDatabase( pStorageDB );
	}
	pIDAClientManager->StartIDAListener( DARUNGRIM2_PORT );

	pOneIDAClientManagerTheSource=new OneIDAClientManager( pStorageDB );
	pOneIDAClientManagerTheTarget=new OneIDAClientManager( pStorageDB );

	pIDAClientManager->AcceptIDAClient( pOneIDAClientManagerTheSource, pDiffMachine? FALSE:pStorageDB?TRUE:FALSE );
	pIDAClientManager->AcceptIDAClient( pOneIDAClientManagerTheTarget, pDiffMachine? FALSE:pStorageDB?TRUE:FALSE );

	if( !pDiffMachine )
	{
		Analyze();
	}

	pIDAClientManager->SetMembers( pOneIDAClientManagerTheSource, pOneIDAClientManagerTheTarget, pDiffMachine );
	pIDAClientManager->CreateIDACommandProcessorThread();
	pIDAClientManager->StopIDAListener();

	return TRUE;
}

bool DarunGrim::OpenDatabase()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	if( pStorageDB )
		delete pStorageDB;

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
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	int source_file_id=1;
	int target_file_id=2;

	if( pOneIDAClientManagerTheSource && pOneIDAClientManagerTheTarget )
	{
		pDiffMachine = new DiffMachine( pOneIDAClientManagerTheSource, pOneIDAClientManagerTheTarget );
	}
	else if( pStorageDB )
	{
		pDiffMachine = new DiffMachine();
		pDiffMachine->Retrieve( *pStorageDB,TRUE,source_file_id,target_file_id);
	}

	if( pDiffMachine )
	{
		pDiffMachine->Analyze();
		pDiffMachine->Save( *pStorageDB );
	}
	return TRUE;
}

bool DarunGrim::ShowOnIDA()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	//pDiffMachine->PrintMatchMapInfo();
	if( pIDAClientManager )
	{
		pIDAClientManager->SetMembers(
			pOneIDAClientManagerTheSource,
			pOneIDAClientManagerTheTarget,
			pDiffMachine
		);
		pIDAClientManager->ShowResultsOnIDA();
		pIDAClientManager->IDACommandProcessor();
		return TRUE;
	}
	return FALSE;
}
