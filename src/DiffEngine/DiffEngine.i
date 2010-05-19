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
%}
%inline %{
	unsigned long GetDWORD(unsigned long *a,int index) {
		return a[index];
	}
%}
class OneIDAClientManager
{
public:
        BOOL RetrieveFromSocket(SOCKET socket);
        BOOL Retrieve(char *DataFile);
	void Save(char *DataFile);
	AnalysisInfo *GetClientAnalysisInfo();
	FileInfo *GetClientFileInfo();
	OneIDAClientManager();
	void DumpAnalysisInfo();
	void GetName(unsigned long address,char *buffer,int len);
	void DumpBlockInfo(unsigned long block_address);
	const char *GetFingerPrint(unsigned long address);
	void RemoveFromFingerprintHash(unsigned long address);
	unsigned long GetBlockAddress(unsigned long address);
	unsigned long *GetMappedAddresses(unsigned long address,int type,int *OUTPUT);
	BOOL SendTLVData(char type,PBYTE data,unsigned long data_length);
	char *GetDisasmLines(unsigned long start_addr,unsigned long end_addr);
        void FreeDisasmLines();
	void ShowAddress(unsigned long address);
};

class IDAClientManager
{
public:
	IDAClientManager(unsigned short port);
	OneIDAClientManager *GetOneIDAClientManagerFromSocket();
        OneIDAClientManager *GetOneIDAClientManagerFromFile(char *DataFile);
	DWORD IDACommandProcessor(OneIDAClientManager *OneIDAClientManagerBefore,OneIDAClientManager *OneIDAClientManagerAfter,DiffMachine *ADiffMachine);
};

typedef struct _FileInfo_ 
{
	char orignal_file_path[100];
	char ComputerName[100];
	char UserName[100];
	char company_name_str[100];
	char file_version_str[100];
	char file_description_str[100];
	char internal_name_str[100];
	char product_name_str[100];
	char modified_time_str[100];
	char md5_sum_str[100];
} FileInfo,*PFileInfo;

typedef struct _MatchInfo_
{
	unsigned long addr;
	unsigned long end_addr;
	unsigned long block_type;
	int match_rate;
	char name[40];
	unsigned long type;
	unsigned long match_addr;
	char match_name[40];
	int first_found_match;
	int first_not_found_match;
	int first_found_match_with_difference;
	int second_found_match;
	int second_not_found_match;
	int second_found_match_with_difference;
} MatchInfo;

typedef struct _CodeBlock_
{
	unsigned long start_addr;
	unsigned long end_addr;
} CodeBlock;

class DiffMachine
{
public:
	DiffMachine(OneIDAClientManager *before,OneIDAClientManager *after);
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
	void ShowDiffMap(unsigned long unpatched_address,unsigned long patched_address);
	void PrintMatchMapInfo();
	void ShowResultsOnIDA();
	bool Analyze();
	void AnalyzeFunctionSanity();
	unsigned long GetMatchAddr(int index,unsigned long address);
	int GetMatchInfoCount();
	MatchInfo GetMatchInfo(int i);
	int GetUnidentifiedBlockCount(int index);
	CodeBlock GetUnidentifiedBlock(int index,int i);
	BOOL Save(char *DataFile);
	BOOL Retrieve(char *DataFile);
};
