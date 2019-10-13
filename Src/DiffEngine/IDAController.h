#pragma once
#pragma warning(disable:4200)
#include <windows.h>
#include <winsock.h>
#include <hash_map>
#include <list>
#include <unordered_set>

#include "Common.h"
#include "DataStructure.h"
#include "SharedMemory.h"
#include "SharedSocket.h"
#include "DisassemblyStorage.h"

using namespace std;
using namespace stdext;

typedef struct
{
	DWORD Start;
	DWORD End;
} BLOCK;

class IDAController
{
private:
#ifndef USE_LEGACY_MAP
	int m_FileID;
#endif
    DisassemblyStorage *m_disassemblyStorage;
	char *m_OriginalFilePath;
	DWORD TargetFunctionAddress;

	SOCKET Socket;
	AnalysisInfo *ClientAnalysisInfo;
	DataSharer IDADataSharer;
	char *DisasmLine;
	void LoadIDARawData(PBYTE (*RetrieveCallback)(PVOID Context, BYTE *Type, DWORD *Length), PVOID Context);
	void GenerateTwoLevelFingerPrint();
	void MergeBlocks();
public:
	SOCKET GetSocket()
	{
		return Socket;
	}
	AnalysisInfo *GetClientAnalysisInfo()
	{
		return ClientAnalysisInfo;
	}
	FileInfo *GetClientFileInfo()
	{
		return &ClientAnalysisInfo->file_info;
	}
	IDAController(DisassemblyStorage *disassemblyStorage=NULL);
	~IDAController();
	BOOL LoadIDARawDataFromFile(const char *Filename);
	void SetSocket(SOCKET socket);
	BOOL LoadIDARawDataFromSocket(SOCKET socket);
	BOOL Retrieve(char *DataFile, DWORD Offset=0L, DWORD Length=0L);

	void SetFileID(int FileID = 1);
	void LoadMapInfo(multimap <DWORD, PMapInfo> *p_map_info_map, DWORD Address, bool IsFunction = false);
	BOOL Load();
	void DeleteMatchInfo(DisassemblyStorage *disassemblyStorage, int FileID=1, DWORD FunctionAddress = 0 );

	void AddAnalysisTargetFunction(DWORD FunctionAddress);
	BOOL LoadBasicBlock();

	BOOL Save(char *DataFile, DWORD Offset=0L, DWORD dwMoveMethod=FILE_BEGIN, unordered_set <DWORD> *pSelectedAddresses=NULL);
	void DumpAnalysisInfo();
	char *GetName(DWORD address);
	void DumpBlockInfo(DWORD block_address);
	char *GetFingerPrintStr(DWORD address);
	void RemoveFromFingerprintHash(DWORD address);
	DWORD GetBlockAddress(DWORD address);
	DWORD *GetMappedAddresses(DWORD address, int type, int *p_length);
	BOOL SendTLVData(char type, PBYTE data, DWORD data_length);
	char *GetDisasmLines(unsigned long start_addr, unsigned long end_addr);

	string Identity;

	multimap <DWORD, DWORD> CrefToMap;
	void BuildCrefToMap(multimap <DWORD, PMapInfo> *p_map_info_map);

	multimap <DWORD, DWORD> BlockToFunction;
	multimap <DWORD, DWORD> FunctionToBlock;
	unordered_set <DWORD> FunctionHeads;
public:
	bool GetFunctionAddress(DWORD address, DWORD &function_address)
	{
		multimap <DWORD, DWORD>::iterator it = BlockToFunction.find(address);

		if (it != BlockToFunction.end())
		{
			function_address = it->second;
			return true;
		}
		function_address = 0;
		return false;
	}

	bool FindBlockFunctionMatch(DWORD block, DWORD function)
	{
		for (multimap <DWORD, DWORD>::iterator it = BlockToFunction.find(block);
			it != BlockToFunction.end() && it->first==block;
			it++)
		{
			if (it->second == function)
			{
				return true;
			}
		}
		return false;
	}

	void LoadBlockToFunction();
	multimap <DWORD, DWORD> *GetFunctionToBlock();
	void ClearBlockToFunction()
	{
		BlockToFunction.clear();
		FunctionToBlock.clear();
	}

	string GetInputName();
	void RetrieveIdentity();
	string GetIdentity();

	PBasicBlock GetBasicBlock(DWORD address);
	void FreeDisasmLines();
	void JumpToAddress(unsigned long address);
	void ColorAddress(unsigned long start_address, unsigned long end_address, unsigned long color);
	list <BLOCK> GetFunctionMemberBlocks(unsigned long FunctionAddress);
	void GenerateFingerprintHashMap();
	int GetFileID();
	char *GetOriginalFilePath();

	BOOL FixFunctionAddresses();
	list <DWORD> *GetFunctionAddresses();

	bool SendMatchedAddrTLVData(FunctionMatchInfo &Data);
	bool SendAddrTypeTLVData(int Type, DWORD Start, DWORD End);
};

unsigned char HexToChar(char *Hex);
unsigned char *HexToBytes(char *HexBytes, int *pLen);
unsigned char *HexToBytesWithLengthAmble(char *HexBytes);
char *BytesWithLengthAmbleToHex(unsigned char *Bytes);
int IsEqualByteWithLengthAmble(unsigned char *Bytes01, unsigned char *Bytes02);
