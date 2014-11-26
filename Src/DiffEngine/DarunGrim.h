#pragma once
#include <windows.h>
#include "Configuration.h"
#include "DiffMachine.h"
#include "DataBaseWriter.h"

#include <string>
using namespace std;
using namespace stdext;

#define DATA_BUFSIZE 4096
#define DEFAULT_IDA_PATH TEXT( "c:\\Program Files\\IDA\\idag.exe" )
#define DEFAULT_IDA64_PATH TEXT( "c:\\Program Files\\IDA\\idag64.exe" )

enum { SOURCE_CONTROLLER, TARGET_CONTROLLER };

class DarunGrim
{
private:
	IDAController *pSourceController;
	IDAController *pTargetController;

	DBWrapper *pStorageDB;
	DiffMachine *pDiffMachine;
	bool OpenDatabase(char *storage_filename);
	string SourceFilename;
	string SourceIDBFilename;
	string TargetFilename;
	string TargetIDBFilename;
	bool IsLoadedSourceFile;
	bool IDAAutoMode;
	DumpAddressChecker aDumpAddress;

public:
	DarunGrim();
	~DarunGrim();


	void AddSrcDumpAddress(DWORD address)
	{
		aDumpAddress.AddSrcDumpAddress(address);
	}

	void AddTargetDumpAddress(DWORD address)
	{
		aDumpAddress.AddTargetDumpAddress(address);
	}


	DiffMachine *GetDiffMachine()
	{
		return pDiffMachine;
	}

	IDAController *GetSourceClientManager()
	{
		return pSourceController;
	}

	IDAController *GetTargetClientManager()
	{
		return pTargetController;
	}

	void JumpToAddress(DWORD address, DWORD type)
	{
		if (type == SOURCE_CONTROLLER)
		{
			if (pSourceController)
			{
				pSourceController->JumpToAddress(address);
			}
		}
		else
		{
			if (pTargetController)
			{
				pTargetController->JumpToAddress(address);
			}
		}
	}

	void ShowReverseAddress(DWORD address, DWORD type)
	{
		if (type == TARGET_CONTROLLER)
		{
			if (pSourceController)
			{
				pSourceController->JumpToAddress(address);
			}
		}
		else
		{
			if (pTargetController)
			{
				pTargetController->JumpToAddress(address);
			}
		}
	}

	char *GetSourceOrigFilename()
	{
		if (pSourceController)
		{
			char *filename = pSourceController->GetOriginalFilePath();
		}
		return NULL;
	}

	char *GetTargetOrigFilename()
	{
		if (pTargetController)
		{
			return pTargetController->GetOriginalFilePath();
		}
		return NULL;
	}

	list <BLOCK> GetSourceAddresses(DWORD address)
	{
		return pSourceController->GetFunctionMemberBlocks(address);
	}

	list <BLOCK> GetTargetAddresses(DWORD address)
	{
		return pTargetController->GetFunctionMemberBlocks(address);
	}

	void SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL );

	bool AcceptIDAClientsFromSocket( const char *storage_filename = NULL );
	
	void ListDiffDatabase(const char *storage_filename);
	bool Load( const char *storage_filename );

	bool PerformDiff();
	bool PerformDiff(const char *src_storage_filename, DWORD source_address, const char *target_storage_filename, DWORD target_address, const char *output_storage_filename);


	bool ShowOnIDA();

	const char *GetSourceFilename();
	const char *GetSourceIDBFilename();
	void SetSourceFilename( char *source_filename );
	const char *GetTargetFilename();
	const char *GetTargetIDBFilename();
	void SetTargetFilename( char *target_filename );
	bool LoadedSourceFile();
	void SetLoadedSourceFile( bool is_loaded );

	void JumpToAddresses( unsigned long source_address, unsigned long target_address );
	void ColorAddress(int type, unsigned long start_address, unsigned long end_address, unsigned long color);

private:
	DBWrapper *m_OutputDB;
	unsigned short ListeningPort;
	SOCKET ListeningSocket;
	IDAController *IDAControllers[2];

	char *IDAPath;
	char *IDA64Path;
	DWORD IDACommandProcessorThreadId;
	char IDALogFilename[MAX_PATH + 1];

	bool GenerateIDALogFilename();
	char *EscapeFilename(char *filename);
	char *LogFilename;
	PSLIST_HEADER pIDAClientListHead;
	vector<IDAController *> IDAControllerList;
	void UpdateIDAControllers();

	bool SetController(int type, const char *identity);
	string SourceIdentity;
	string TargetIdentity;
public:

	void SetDatabase(DBWrapper *OutputDB);
	unsigned short StartIDAListenerThread(unsigned short port);
	void ListIDAControllers();
	IDAController *FindIDAController(const char *identity);
	bool SetSourceController(const char *identity);
	bool SetTargetController(const char *identity);

	bool StartIDAListener(unsigned short port);
	bool StopIDAListener();

	IDAController *GetIDAControllerFromFile(char *DataFile);
	DWORD SetMembers(DiffMachine *pArgDiffMachine);
	DWORD IDACommandProcessor();
	BOOL CreateIDACommandProcessorThread();
	void SetIDAPath(const char *ParamIDAPath, bool is_64);
	void SetLogFilename(char *logfilename)
	{
		LogFilename = EscapeFilename(logfilename);
	}
	void GenerateSourceDGFFromIDA(char *output_filename, char *log_filename, bool is_64);
	void GenerateTargetDGFFromIDA(char *output_filename, char *log_filename, bool is_64);
	void GenerateDGFFromIDA(const char *ida_filename, unsigned long StartAddress, unsigned long EndAddress, char *output_filename, char *log_filename,bool is_64);
	void ConnectToDarunGrim(const char *ida_filename);
	void SetIDALogFilename(const char *ida_log_filename);
	const char *GetIDALogFilename();
	BOOL AcceptIDAClient(IDAController *p_ida_controller, bool retrieve_Data);
	void SetAutoMode(bool mode)
	{
		IDAAutoMode = mode;
	}
};
