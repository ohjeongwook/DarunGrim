#pragma once
#include <windows.h>
#include "IDAClientManager.h"

class DarunGrim
{
private:
	IDAClientManager aIDAClientManager;
public:
	DarunGrim();
	~DarunGrim();
	void SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL );
	void SetIDAPath( const char *path );
	void RunIDAToGenerateDB( char *StorageFilename, 
		char *LogFilename, 
		char *TheSourceFilename, DWORD StartAddressForSource, DWORD EndAddressForSource, 
		char *TheTargetFilename, DWORD StartAddressForTarget, DWORD EndAddressForTarget );
};
