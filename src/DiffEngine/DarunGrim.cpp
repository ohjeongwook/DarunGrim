#include "Common.h"
#include "DarunGrim.h"
#include "LogOperation.h"

LogOperation Logger;

DarunGrim::DarunGrim(): 
	pStorageDB(NULL),
	pOneIDAClientManagerTheSource(NULL),
	pOneIDAClientManagerTheTarget(NULL),
	pDiffMachine(NULL),
	pIDAClientManager(NULL),
	SourceFilename(NULL),
	TargetFilename(NULL)
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
	DWORD start_address_for_source, DWORD end_address_for_source, 
	DWORD start_address_for_target, DWORD end_address_for_target )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	StorageFilename = ParamStorageFilename;

	pIDAClientManager->SetOutputFilename(StorageFilename);
	pIDAClientManager->SetLogFilename(LogFilename);
	pIDAClientManager->RunIDAToGenerateDB( SourceFilename, start_address_for_source, end_address_for_source );
	pIDAClientManager->RunIDAToGenerateDB( TargetFilename, start_address_for_target, end_address_for_target );
	return OpenDatabase();
}

DWORD WINAPI ConnectToDarunGrim2Thread( LPVOID lpParameter )
{
	DarunGrim *pDarunGrim=( DarunGrim * )lpParameter;
	IDAClientManager *pIDAClientManager;

	if( pDarunGrim && (pIDAClientManager = pDarunGrim->GetIDAClientManager()) )
	{
		pIDAClientManager->ConnectToDarunGrim2( pDarunGrim->GetSourceFilename() );
		pIDAClientManager->ConnectToDarunGrim2( pDarunGrim->GetTargetFilename() );
	}
	return 1;
}

char *DarunGrim::GetSourceFilename()
{
	return SourceFilename;
}

void DarunGrim::SetSourceFilename( char *source_filename )
{
	SourceFilename = source_filename;
}

char *DarunGrim::GetTargetFilename()
{
	return TargetFilename;
}

void DarunGrim::SetTargetFilename( char *target_filename )
{
	TargetFilename = target_filename;
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

	//Create a thread that will call ConnectToDarunGrim2 one by one
	DWORD dwThreadId;
	CreateThread( NULL, 0, ConnectToDarunGrim2Thread, ( PVOID )this, 0, &dwThreadId );

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

bool DarunGrim::LoadDiffResults( const char *storage_filename )
{
	pStorageDB = new DBWrapper( (char *) storage_filename );
	if( pStorageDB )
	{
		pDiffMachine = new DiffMachine();

		if( pDiffMachine )
		{
			pDiffMachine->Retrieve( *pStorageDB,TRUE, 1 , 2 );
			return TRUE;
		}
	}
	return FALSE;
}

bool DarunGrim::Analyze()
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	int source_file_id=1;
	int target_file_id=2;

	if( pStorageDB )
	{
		pDiffMachine = new DiffMachine();
		pDiffMachine->Retrieve( *pStorageDB,TRUE,source_file_id,target_file_id);
	}
	else if( pOneIDAClientManagerTheSource && pOneIDAClientManagerTheTarget )
	{
		pDiffMachine = new DiffMachine( pOneIDAClientManagerTheSource, pOneIDAClientManagerTheTarget );
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

IDAClientManager *DarunGrim::GetIDAClientManager()
{
	return pIDAClientManager;
}
