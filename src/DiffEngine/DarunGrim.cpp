#include "DarunGrim.h"
#include "LogOperation.h"

LogOperation Logger;

DarunGrim::DarunGrim(): pOneIDAClientManagerTheSource(NULL), pOneIDAClientManagerTheTarget(NULL)
{
	pIDAClientManager = new IDAClientManager();
}

DarunGrim::~DarunGrim()
{
	if( pStorageDB )
	{
		pStorageDB->CloseDatabase();
		delete pStorageDB;
	}

	if( pOneIDAClientManagerTheSource )
		delete pOneIDAClientManagerTheSource;

	if( pOneIDAClientManagerTheTarget )
		delete pOneIDAClientManagerTheTarget;

	if( pDiffMachine )
		delete pDiffMachine;

	delete pIDAClientManager;

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
		pIDAClientManager->SetIDAPath( path );
}

bool DarunGrim::GenerateDB( 
	char *ParamStorageFilename, 
	char *LogFilename, 
	char *TheSourceFilename, DWORD StartAddressForSource, DWORD EndAddressForSource, 
	char *TheTargetFilename, DWORD StartAddressForTarget, DWORD EndAddressForTarget )
{
	StorageFilename = ParamStorageFilename;

	printf("TheSourceFilename=%s\nTheTargetFilename=%s\nStorageFilename=%s\n",
		TheSourceFilename,TheTargetFilename,StorageFilename);

	pIDAClientManager->SetOutputFilename(StorageFilename);
	pIDAClientManager->SetLogFilename(LogFilename);
	pIDAClientManager->RunIDAToGenerateDB(TheSourceFilename,StartAddressForSource,EndAddressForSource);
	pIDAClientManager->RunIDAToGenerateDB(TheTargetFilename,StartAddressForTarget,EndAddressForTarget);
	return OpenDatabase();
}

bool DarunGrim::GenerateDB()
{
	pIDAClientManager->SetDatabase( pStorageDB );
	pIDAClientManager->StartIDAListener( DARUNGRIM2_PORT );
	pOneIDAClientManagerTheSource=new OneIDAClientManager( pStorageDB );
	pOneIDAClientManagerTheTarget=new OneIDAClientManager( pStorageDB );

	pIDAClientManager->AssociateSocket( pOneIDAClientManagerTheSource, TRUE );
	pIDAClientManager->AssociateSocket( pOneIDAClientManagerTheTarget, TRUE );

	//Run idc for each file
	/*
	Create temporary IDC file: <idc filename>
	"static main()
	{
		RunPlugin("DarunGrim2",1);
		SendDiassemblyInfo("%s");
		Exit(0);
	}",StorageFilename
	Execute "c:\program files\IDA\idag" -A -S<idc filename> <filename> for each file
	*/
	return TRUE;
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

	if( pOneIDAClientManagerTheSource && pOneIDAClientManagerTheTarget )
	{
		pDiffMachine=new DiffMachine( pOneIDAClientManagerTheSource, pOneIDAClientManagerTheTarget );
	}
	else
	{
		pDiffMachine=new DiffMachine();
		pDiffMachine->Retrieve( *pStorageDB,TRUE,TheSourceFileID,TheTargetFileID);
	}

	pDiffMachine->Analyze();
	pDiffMachine->Save( *pStorageDB );
	return TRUE;
}

bool DarunGrim::ShowOnIDA()
{
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
