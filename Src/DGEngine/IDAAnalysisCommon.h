#pragma warning(disable:4200)
#pragma once

#include "windows.h"

typedef int va_t;
#define strtoul10(X) strtoul(X, NULL, 10)

#pragma pack(push)
#pragma pack(1)
enum { BASIC_BLOCK,MAP_INFO,FILE_INFO,END_OF_DATA, DISASM_LINES, INPUT_NAME};
//DISASM_LINES,FINGERPRINT_INFO,NAME_INFO
enum {UNKNOWN_BLOCK,FUNCTION_BLOCK};
//MapInfo
//Pushing Map information
enum {CALL,CREF_FROM,CREF_TO,DREF_FROM,DREF_TO,CALLED};

typedef struct _MapInfo_ {
	BYTE Type;
	va_t SrcBlock;
	va_t SrcBlockEnd;
	va_t Dst;
} MapInfo,*PMapInfo;

//BasicBlock
//Pushing Basic Information on Address

typedef struct _BasicBlock_ {
	va_t StartAddress; //ea_t
	va_t EndAddress;
	BYTE Flag; //Flag_t
	//func_t get_func(current_addr)
	va_t FunctionAddress;
	BYTE BlockType; // FUNCTION, UNKNOWN
	int NameLen;
	int DisasmLinesLen;
	int FingerprintLen;
	int CmdArrayLen;
	char Data[0];
} BasicBlock, *PBasicBlock;

typedef struct _FileInfo_ 
{
	TCHAR OriginalFilePath[MAX_PATH+1];
	TCHAR ComputerName[100];
	TCHAR UserName[100];
	TCHAR CompanyName[100];
	TCHAR FileVersion[100];
	TCHAR FileDescription[100];
	TCHAR InternalName[100];
	TCHAR ProductName[100];
	TCHAR ModifiedTime[100];
	TCHAR MD5Sum[100];
} FileInfo,*PFileInfo;

#define DREF 0
#define CREF 1
#define FUNCTION 2
#define STACK 3
#define NAME 4
#define DISASM_LINE 5
#define DATA_TYPE 6

#pragma pack(pop)
