#pragma once
#include <windows.h>
#include "IDAClientManager.h"
#include "Configuration.h"
#include "DiffMachine.h"
#include "DataBaseWriter.h"

#include <string>
using namespace std;
using namespace stdext;

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
	string SourceFilename;
	string SourceIDBFilename;
	string TargetFilename;
	string TargetIDBFilename;
	bool IsLoadedSourceFile;
public:
	DarunGrim();
	~DarunGrim();
	void SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL );
	void SetIDAPath( const char *path );
	bool GenerateDB( 
		char *storage_filename, 
		char *log_filename, 
		char *ida_log_filename_for_source,
		char *ida_log_filename_for_target,
		unsigned long start_address_for_source, unsigned long end_address_for_source, 
		unsigned long start_address_for_target, unsigned long end_address_for_target );
	bool AcceptIDAClientsFromSocket( const char *storage_filename = NULL );

	bool LoadDiffResults( const char *storage_filename );
	bool Analyze();
	bool ShowOnIDA();

	const char *GetSourceFilename();
	const char *GetSourceIDBFilename();
	void SetSourceFilename( char *source_filename );
	const char *GetTargetFilename();
	const char *GetTargetIDBFilename();
	void SetTargetFilename( char *target_filename );
	IDAClientManager *GetIDAClientManager();

	bool LoadedSourceFile();
	void SetLoadedSourceFile( bool is_loaded );

	void ShowAddresses( unsigned long source_address, unsigned long target_address );
	void ColorAddress( int index, unsigned long start_address, unsigned long end_address,unsigned long color );
};
