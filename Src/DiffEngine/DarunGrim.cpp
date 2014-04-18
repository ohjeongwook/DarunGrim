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
	IsLoadedSourceFile( false )	
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

void DarunGrim::SetLogParameters(int newLogOutputType, int newDebugLevel, const char *newLogFile)
{
	printf("SetLogParameters: %d %d %s\n", newLogOutputType, newDebugLevel, newLogFile);
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );
	Logger.SetOutputType(newLogOutputType);
	if (newLogFile)
		Logger.SetLogFilename(newLogFile);
	Logger.SetDebugLevel(newDebugLevel);
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

bool DarunGrim::DiffDatabaseFiles(char *src_storage_filename, DWORD source_address, char *target_storage_filename, DWORD target_address, char *output_storage_filename)
{
	Logger.Log(10, "%s: entry (%s)\n", __FUNCTION__, output_storage_filename);

	pDiffMachine = new DiffMachine();
	pDiffMachine->SetSource((char *)src_storage_filename, 1, source_address);
	pDiffMachine->SetTarget((char *)target_storage_filename, 1, target_address);
	pDiffMachine->SetLoadOneIDAClientManager(true);
	pDiffMachine->Load((char *)output_storage_filename);

	Logger.Log(10, "Analyze\n");
	pDiffMachine->Analyze();

	if (pStorageDB)
		delete pStorageDB;

	Logger.Log(10, "Save\n");
	pStorageDB = new DBWrapper((char *)output_storage_filename);
	pIDAClientManager->SetDatabase(pStorageDB);

	pDiffMachine->Save(*pStorageDB);
	return TRUE;
}

bool DarunGrim::OpenDatabase(char *storage_filename)
{
	Logger.Log(10, "%s: entry\n", __FUNCTION__ );

	if( pStorageDB )
		delete pStorageDB;

	pStorageDB = new DBWrapper(storage_filename);

	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_FUNCTION_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_START_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_ONE_LOCATION_INFO_TABLE_END_ADDRESS_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_MAP_INFO_TABLE_SRCBLOCK_INDEX_STATEMENT);
	pStorageDB->ExecuteStatement(NULL, NULL, CREATE_FILE_INFO_TABLE_STATEMENT);
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
			pDiffMachine->SetRetrieveDataForAnalysis(TRUE);
			pDiffMachine->SetSource(pStorageDB, 1);
			pDiffMachine->SetTarget(pStorageDB, 2);
			pDiffMachine->Load(pStorageDB);
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
		pDiffMachine->SetRetrieveDataForAnalysis(TRUE);
		pDiffMachine->SetSource(pStorageDB, source_file_id);
		pDiffMachine->SetSource(pStorageDB, target_file_id);
		pDiffMachine->Load(pStorageDB);
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
