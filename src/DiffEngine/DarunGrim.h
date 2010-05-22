#pragma once
#include <windows.h>
#include "IDAClientManager.h"
#include "Configuration.h"
#include "DiffMachine.h"
#include "DataBaseWriter.h"

class DarunGrim
{
private:
	IDAClientManager aIDAClientManager;
	DBWrapper *pStorageDB;
	DiffMachine *pDiffMachine;
	bool OpenDatabase();
	char *StorageFilename;
public:
	DarunGrim();
	~DarunGrim();
	void SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL );
	void SetIDAPath( const char *path );
	bool RunIDAToGenerateDB( char *StorageFilename, 
		char *LogFilename, 
		char *TheSourceFilename, DWORD StartAddressForSource, DWORD EndAddressForSource, 
		char *TheTargetFilename, DWORD StartAddressForTarget, DWORD EndAddressForTarget );
	bool Analyze();
};
