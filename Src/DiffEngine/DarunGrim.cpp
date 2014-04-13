#include "Common.h"
#include "DarunGrim.h"
#include "LogOperation.h"

LogOperation Logger;

DarunGrim::DarunGrim(): 
	pStorageDB(NULL),
	pSourceIDAClientManager(NULL),
	pTargetIDAClientManager(NULL),
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

	if( pSourceIDAClientManager )
		delete pSourceIDAClientManager;

	if( pTargetIDAClientManager )
		delete pTargetIDAClientManager;
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
	char *storage_filename, 
	char *log_filename, 
	char *ida_log_filename_for_source,
	char *ida_log_filename_for_target,
	unsigned long start_address_for_source, unsigned long end_address_for_source, 
	unsigned long start_address_for_target, unsigned long end_address_for_target )
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	pIDAClientManager->SetOutputFilename(storage_filename);
	pIDAClientManager->SetLogFilename( log_filename );
	pIDAClientManager->SetIDALogFilename( ida_log_filename_for_source );
	pIDAClientManager->RunIDAToGenerateDB( SourceFilename.c_str(), start_address_for_source, end_address_for_source );
	pIDAClientManager->SetIDALogFilename( ida_log_filename_for_target );
	pIDAClientManager->RunIDAToGenerateDB( TargetFilename.c_str(), start_address_for_target, end_address_for_target );
	return OpenDatabase(storage_filename);
}

DWORD WINAPI ConnectToDarunGrimThread( LPVOID lpParameter )
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
			pIDAClientManager->ConnectToDarunGrim( filename );
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
	pIDAClientManager->StartIDAListener(DARUNGRIM_PORT);

	pSourceIDAClientManager=new OneIDAClientManager( pStorageDB );
	pTargetIDAClientManager=new OneIDAClientManager( pStorageDB );

	//Create a thread that will call ConnectToDarunGrim one by one
	DWORD dwThreadId;
	CreateThread( NULL, 0, ConnectToDarunGrimThread, ( PVOID )this, 0, &dwThreadId );
	pIDAClientManager->AcceptIDAClient( pSourceIDAClientManager, pDiffMachine? FALSE:pStorageDB?TRUE:FALSE );
	SetLoadedSourceFile( TRUE );

	CreateThread( NULL, 0, ConnectToDarunGrimThread, ( PVOID )this, 0, &dwThreadId );
	pIDAClientManager->AcceptIDAClient( pTargetIDAClientManager, pDiffMachine? FALSE:pStorageDB?TRUE:FALSE );

	if( !pDiffMachine )
	{
		Analyze();
	}

	pIDAClientManager->SetMembers( pSourceIDAClientManager, pTargetIDAClientManager, pDiffMachine );
	pIDAClientManager->CreateIDACommandProcessorThread();
	pIDAClientManager->StopIDAListener();

	return TRUE;
}

bool DarunGrim::DiffDatabaseFiles(char *src_storage_filename, char *target_storage_filename, char *output_storage_filename)
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__);
	
	printf("%s\n", output_storage_filename);

	pSourceIDAClientManager = new OneIDAClientManager(new DBWrapper((char *)src_storage_filename));
	pTargetIDAClientManager = new OneIDAClientManager(new DBWrapper((char *)target_storage_filename));
	
	printf("Loading %s\n", src_storage_filename);
	pSourceIDAClientManager->Load();

	printf("Loading %s\n", target_storage_filename);
	pTargetIDAClientManager->Load();

	pDiffMachine = new DiffMachine(pSourceIDAClientManager, pTargetIDAClientManager);

	if (pDiffMachine)
	{
		pDiffMachine->Analyze();

		if (pStorageDB)
			delete pStorageDB;

		pStorageDB = new DBWrapper((char *)output_storage_filename);
		pIDAClientManager->SetDatabase(pStorageDB);

		pDiffMachine->Save(*pStorageDB);
	}

	return TRUE;
}

bool DarunGrim::OpenDatabase(char *storage_filename)
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	if( pStorageDB )
		delete pStorageDB;

	pStorageDB = new DBWrapper(storage_filename);

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
			pDiffMachine->Load(*pStorageDB, TRUE, 1, 2);
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
		pDiffMachine->Load(*pStorageDB, TRUE, source_file_id, target_file_id);
	}
	else if( pSourceIDAClientManager && pTargetIDAClientManager )
	{
		pDiffMachine = new DiffMachine( pSourceIDAClientManager, pTargetIDAClientManager );
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
			pSourceIDAClientManager,
			pTargetIDAClientManager,
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
	if( pSourceIDAClientManager )
		pSourceIDAClientManager->ShowAddress( source_address );
	if( pTargetIDAClientManager )
		pTargetIDAClientManager->ShowAddress( target_address );
}

void DarunGrim::ColorAddress( int index, unsigned long start_address, unsigned long end_address,unsigned long color )
{
	if( index == 0 )
	{
		if( pSourceIDAClientManager )
			pSourceIDAClientManager->ColorAddress( start_address, end_address, color );
	}
	else
	{
		if( pTargetIDAClientManager )
			pTargetIDAClientManager->ColorAddress( start_address, end_address, color );
	}
}

IDAClientManager *DarunGrim::GetIDAClientManager()
{
	return pIDAClientManager;
}
