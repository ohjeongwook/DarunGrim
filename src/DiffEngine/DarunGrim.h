#pragma once
#include <windows.h>
#include "IDAClientManager.h"
#include "Configuration.h"
#include "DiffMachine.h"
#include "DataBaseWriter.h"

class DarunGrim
{
private:
	IDAClientManager *pIDAClientManager;
	OneIDAClientManager *pOneIDAClientManagerTheSource;
	OneIDAClientManager *pOneIDAClientManagerTheTarget;

	DBWrapper *pStorageDB;
	DiffMachine *pDiffMachine;
	bool OpenDatabase();
	char *StorageFilename;
	char *SourceFilename;
	char *TargetFilename;
public:
	DarunGrim();
	~DarunGrim();
	void SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL );
	void SetIDAPath( const char *path );
	bool GenerateDB( char *StorageFilename, 
		char *LogFilename, 
		DWORD StartAddressForSource, DWORD EndAddressForSource, 
		DWORD StartAddressForTarget, DWORD EndAddressForTarget );
	bool AcceptIDAClientsFromSocket( const char *storage_filename = NULL );

	bool LoadDiffResults( const char *storage_filename );
	bool Analyze();
	bool ShowOnIDA();

	char *GetSourceFilename();
	void SetSourceFilename( char *source_filename );
	char *GetTargetFilename();
	void SetTargetFilename( char *target_filename );
	IDAClientManager *GetIDAClientManager();
};
