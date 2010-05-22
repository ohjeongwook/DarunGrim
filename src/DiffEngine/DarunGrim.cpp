#include "DarunGrim.h"
#include "LogOperation.h"

LogOperation Logger;

DarunGrim::DarunGrim(): pOneIDAClientManagerTheSource(NULL), pOneIDAClientManagerTheTarget(NULL)
{
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

bool DarunGrim::GenerateDB( 
	char *ParamStorageFilename, 
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

bool DarunGrim::GenerateDB()
{
	IDAClientManager *pIDAClientManager=new IDAClientManager(DARUNGRIM2_PORT, pStorageDB );
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

