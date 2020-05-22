#pragma once
#include "windows.h"
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <vector>

using namespace std;
using namespace stdext;

typedef int va_t;
#define strtoul10(X) strtoul(X, NULL, 10)

enum { SEND_ANALYSIS_DATA, UNINDENTIFIED_ADDR, MATCHED_ADDR, SHOW_DATA, SHOW_MATCH_ADDR, JUMP_TO_ADDR, GET_DISASM_LINES, COLOR_ADDRESS, GET_INPUT_NAME, MODIFIED_ADDR };

//DISASM_LINES,FINGERPRINT_INFO,NAME_INFO
enum { UNKNOWN_BLOCK, FUNCTION_BLOCK };

//Pushing Map information
enum { CALL, CREF_FROM, CREF_TO, DREF_FROM, DREF_TO, CALLED };

enum { BASIC_BLOCK, MAP_INFO, FILE_INFO, END_OF_DATA, DISASM_LINES, INPUT_NAME };

typedef struct _FileInfo_
{
	TCHAR OriginalFilePath[MAX_PATH + 1];
	TCHAR ComputerName[100];
	TCHAR UserName[100];
	TCHAR CompanyName[100];
	TCHAR FileVersion[100];
	TCHAR FileDescription[100];
	TCHAR InternalName[100];
	TCHAR ProductName[100];
	TCHAR ModifiedTime[100];
	TCHAR MD5Sum[100];
} FileInfo,  *PFileInfo;

typedef struct _BasicBlock_ {
	va_t StartAddress; //ea_t
	va_t EndAddress;
	char Flag; //Flag_t
	//func_t get_func(current_addr)
	va_t FunctionAddress;
	char BlockType; // FUNCTION, UNKNOWN
	int NameLen;
	int DisasmLinesLen;
	int FingerprintLen;
	int CmdArrayLen;
	char Data[0];
} BasicBlock,  *PBasicBlock;

typedef struct _CodeBlock_
{
	va_t StartAddress;
	va_t EndAddress;
} CodeBlock;

typedef struct
{
	va_t Start;
	va_t End;
} BLOCK;

typedef struct _MapInfo_ {
	BYTE Type;
	va_t SrcBlock;
	va_t SrcBlockEnd;
	va_t Dst;
} MapInfo,  *PMapInfo;

typedef pair <va_t, PMapInfo> AddressPMapInfoPair;
