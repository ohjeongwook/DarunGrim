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
	IsLoadedSourceFile( FALSE )
{
	LogOperation::InitLog();
	Logger.SetCategory( "DarunGrim" );
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
	Logger.SetOutputType( ParamLogOutputType );
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
	pIDAClientManager->RunIDAToGenerateDB( SourceFilename.c_str(), start_address_for_source, end_address_for_source );
	pIDAClientManager->RunIDAToGenerateDB( TargetFilename.c_str(), start_address_for_target, end_address_for_target );
	return OpenDatabase();
}

DWORD WINAPI ConnectToDarunGrim2Thread( LPVOID lpParameter )
{
	DarunGrim *pDarunGrim=( DarunGrim * )lpParameter;
	IDAClientManager *pIDAClientManager;

	if( pDarunGrim && (pIDAClientManager = pDarunGrim->GetIDAClientManager()) )
	{
		const char *filename = NULL;
		if( !pDarunGrim->LoadedSourceFile() )
		{	
			filename = pDarunGrim->GetSourceIDBFilename();
			if( !filename )
			{
				filename = pDarunGrim->GetSourceFilename();
			}				
		}
		else
		{
			filename = pDarunGrim->GetTargetIDBFilename();
			if( !filename )
			{
				filename = pDarunGrim->GetTargetFilename();
			}
		}

		if( filename )
			pIDAClientManager->ConnectToDarunGrim2( filename );
	}
	return 1;
}

const char *DarunGrim::GetSourceFilename()
{
	return SourceFilename.c_str();
}

const char *DarunGrim::GetSourceIDBFilename()
{
	if( GetFileAttributes( SourceIDBFilename.c_str() ) == INVALID_FILE_ATTRIBUTES )
		return NULL;
	return SourceIDBFilename.c_str();
}

void DarunGrim::SetSourceFilename( char *source_filename )
{
	SourceFilename = source_filename;
	SourceIDBFilename = SourceFilename;
	SourceIDBFilename = SourceIDBFilename.replace ( SourceIDBFilename.length() - 4 , SourceIDBFilename.length() - 1 , ".idb" );	
}

const char *DarunGrim::GetTargetFilename()
{
	return TargetFilename.c_str();
}

const char *DarunGrim::GetTargetIDBFilename()
{
	if( GetFileAttributes( TargetIDBFilename.c_str() ) == INVALID_FILE_ATTRIBUTES )
		return NULL;
	return TargetIDBFilename.c_str();
}

void DarunGrim::SetTargetFilename( char *target_filename )
{
	TargetFilename = target_filename;
	TargetIDBFilename = TargetFilename;
	TargetIDBFilename = TargetIDBFilename.replace ( TargetIDBFilename.length() - 4 , TargetIDBFilename.length() - 1 , ".idb" );	
}

bool DarunGrim::LoadedSourceFile()
{
	return IsLoadedSourceFile;
}

void DarunGrim::SetLoadedSourceFile( bool is_loaded )
{
	IsLoadedSourceFile = is_loaded;
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
	SetLoadedSourceFile( TRUE );

	CreateThread( NULL, 0, ConnectToDarunGrim2Thread, ( PVOID )this, 0, &dwThreadId );
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

void DarunGrim::ShowAddresses( unsigned long source_address, unsigned long target_address )
{
	if( pOneIDAClientManagerTheSource )
		pOneIDAClientManagerTheSource->ShowAddress( source_address );
	if( pOneIDAClientManagerTheTarget )
		pOneIDAClientManagerTheTarget->ShowAddress( target_address );
}

void DarunGrim::ColorAddress( int index, unsigned long start_address, unsigned long end_address,unsigned long color )
{
	if( index == 0 )
	{
		if( pOneIDAClientManagerTheSource )
			pOneIDAClientManagerTheSource->ColorAddress( start_address, end_address, color );
	}
	else
	{
		if( pOneIDAClientManagerTheTarget )
			pOneIDAClientManagerTheTarget->ColorAddress( start_address, end_address, color );
	}
}

IDAClientManager *DarunGrim::GetIDAClientManager()
{
	return pIDAClientManager;
}
