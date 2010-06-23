/* File : DiffEngine.i */
%module DiffEngine
%include typemaps.i

%{
#include <windows.h>
#include "DataStructure.h"
#include "Configuration.h"
#include "IDAClientManager.h"
#include "DiffMachine.h"
#include "OneIDAClientManager.h"
#include "DarunGrim.h"
%}
%inline %{
	unsigned long GetDWORD(unsigned long *a,int index) {
		return a[index];
	}
%}

class DBWrapper
{
public:
	DBWrapper( char *DatabaseName = NULL );
};

class OneIDAClientManager
{
public:
	OneIDAClientManager(DBWrapper *StorageDB=NULL);
	AnalysisInfo *GetClientAnalysisInfo();
	FileInfo *GetClientFileInfo();
	void DumpAnalysisInfo();
	//void GetName(unsigned long address,char *buffer,int len);
	void DumpBlockInfo(unsigned long block_address);
	//const char *GetFingerPrint(unsigned long address);
	void RemoveFromFingerprintHash(unsigned long address);
	unsigned long GetBlockAddress(unsigned long address);
	unsigned long *GetMappedAddresses(unsigned long address,int type,int *OUTPUT);
	char *GetDisasmLines(unsigned long start_addr,unsigned long end_addr);
	void FreeDisasmLines();
	void ShowAddress(unsigned long address);
};

class IDAClientManager
{
public:
	IDAClientManager();

	void SetDatabase( DBWrapper *OutputDB );
	bool StartIDAListener( unsigned short port );

	void SetIDAPath( const char *ParamIDAPath );
	void SetOutputFilename(char *OutputFilename);
	void SetLogFilename(char *LogFilename);
	void RunIDAToGenerateDB(char *ida_filename,unsigned long StartAddress,unsigned long EndAddress);
	void ConnectToDarunGrim2(char *ida_filename);
};

class DiffMachine
{
public:
	DiffMachine( OneIDAClientManager *the_source=NULL, OneIDAClientManager *the_target=NULL );
	/*
	void DumpMatchMapIterInfo(multimap <unsigned long, MappingData>::iterator match_map_iter);
	void GetMatchStatistics(
		unsigned long address,
		OneIDAClientManager *ClientManager,
		multimap <unsigned long,MappingData> *p_match_map,
		int *p_found_match_number,
		int *p_found_match_with_difference_number,
		int *p_not_found_match_number);
	int GetMatchRate(unsigned long unpatched_address,unsigned long patched_address);
	void DoFingerPrintMatch(multimap <unsigned long,MappingData> *p_match_map);
	*/
	void ShowDiffMap(unsigned long unpatched_address,unsigned long patched_address);
	void PrintMatchMapInfo();
	//void ShowResultsOnIDA();
	bool Analyze();
	void AnalyzeFunctionSanity();
	unsigned long GetMatchAddr(int index,unsigned long address);
	//int GetMatchInfoCount();
	//MatchInfo GetMatchInfo(int i);
	int GetUnidentifiedBlockCount(int index);
	CodeBlock GetUnidentifiedBlock(int index,int i);
	
	BOOL Retrieve( DBWrapper& InputDB, BOOL bRetrieveDataForAnalysis=TRUE, int TheSourceFileID=1, int TheTargetFileID=2, BOOL bLoadMatchMapToMemory=FALSE );
	BOOL Save( DBWrapper& OutputDB, hash_set <DWORD> *pTheSourceSelectedAddresses=NULL, hash_set <DWORD> *pTheTargetSelectedAddresses=NULL );
};

class DarunGrim
{
public:
	void SetLogParameters( int ParamLogOutputType, int ParamDebugLevel, const char *LogFile = NULL );
	void SetIDAPath( const char *path );
	bool GenerateDB(
		char *StorageFilename, 
		char *LogFilename, 
		int StartAddressForSource, int EndAddressForSource, 
		int StartAddressForTarget, int EndAddressForTarget );
	bool AcceptIDAClientsFromSocket( const char *storage_filename = NULL );
	bool Analyze();
	
	void SetSourceFilename( char *source_filename );
	void SetTargetFilename( char *target_filename );	
	
	bool LoadDiffResults( const char *storage_filename );
	void ShowAddresses( unsigned long source_address, unsigned long target_address );
	void ColorAddress( int index, unsigned long start_address, unsigned long end_address );
};