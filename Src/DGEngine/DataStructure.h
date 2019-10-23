#pragma once

#include <unordered_set>
#include <unordered_map>

#include "Common.h"
#include "DataStructure.h"
#include "windows.h"

using namespace std;
using namespace stdext;

typedef int va_t;
#define strtoul10(X) strtoul(X, NULL, 10)

#pragma pack(push)
#pragma pack(1)

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
} FileInfo, * PFileInfo;

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
} BasicBlock, * PBasicBlock;

#define DREF 0
#define CREF 1
#define FUNCTION 2
#define STACK 3
#define NAME 4
#define DISASM_LINE 5
#define DATA_TYPE 6

typedef struct
{
	va_t Start;
	va_t End;
} BLOCK;

struct FileList
{
	string SourceFilename;
	string TargetFilename;
};

enum { BASIC_BLOCK, MAP_INFO, FILE_INFO, END_OF_DATA, DISASM_LINES, INPUT_NAME };
//DISASM_LINES,FINGERPRINT_INFO,NAME_INFO
enum { UNKNOWN_BLOCK, FUNCTION_BLOCK };
//MapInfo
//Pushing Map information
enum { CALL, CREF_FROM, CREF_TO, DREF_FROM, DREF_TO, CALLED };

typedef struct _MapInfo_ {
	BYTE Type;
	va_t SrcBlock;
	va_t SrcBlockEnd;
	va_t Dst;
} MapInfo, * PMapInfo;

typedef struct _FingerPrintInfo_ {
    va_t addr;
} FingerPrintInfo, * PFingerPrintInfo;

typedef struct _FunctionMatchInfo_
{
    va_t TheSourceAddress;
    va_t EndAddress;
    va_t TheTargetAddress;
    short BlockType;
    short MatchRate;
    char* TheSourceFunctionName;
    short Type;
    char* TheTargetFunctionName;
    int MatchCountForTheSource;
    int NoneMatchCountForTheSource;
    int MatchCountWithModificationForTheSource;
    int MatchCountForTheTarget;
    int NoneMatchCountForTheTarget;
    int MatchCountWithModificationForTheTarget;
} FunctionMatchInfo;

typedef struct _CodeBlock_
{
    va_t StartAddress;
    va_t EndAddress;
} CodeBlock;

enum { SEND_ANALYSIS_DATA, UNINDENTIFIED_ADDR, MATCHED_ADDR, SHOW_DATA, SHOW_MATCH_ADDR, JUMP_TO_ADDR, GET_DISASM_LINES, COLOR_ADDRESS, GET_INPUT_NAME, MODIFIED_ADDR };


#include <map>
using namespace std;

class hash_compare_fingerprint
{
public:
    enum
    {
        bucket_size = 400000,
        min_buckets = 4000
    };
public:
    size_t operator() (/*[in]*/ const unsigned char* Bytes) const
    {
        size_t Key = 0;
        for (int i = 0; i < *(unsigned short*)Bytes; i++)
        {
            Key += Bytes[sizeof(short) + i];
        }
        return  Key;
    }
public:
    bool operator() (/*[in]*/const unsigned char* Bytes01,/*[in]*/ const unsigned char* Bytes02) const
    {
        if (Bytes01 == Bytes02)
        {
            return 0;
        }

        if (*(unsigned short*)Bytes01 == *(unsigned short*)Bytes02)
        {
            return (memcmp(Bytes01 + sizeof(unsigned short), Bytes02 + sizeof(unsigned short), *(unsigned short*)Bytes01) < 0);
        }
        return (*(unsigned short*)Bytes01 > * (unsigned short*)Bytes02);
    }
};

//,hash_compare<string,equ_str> 
typedef struct _AnalysisInfo_ {
    FileInfo file_info;
    multimap <va_t, PBasicBlock> address_map;
    multimap <va_t, string> address_disassembly_map;
    multimap <unsigned char*, va_t, hash_compare_fingerprint> fingerprint_map;
    multimap <va_t, unsigned char*> address_fingerprint_map;
    multimap <string, va_t> name_map;
    multimap <va_t, string> address_name_map;
    multimap <va_t, PMapInfo> map_info_map;
} AnalysisInfo, * PAnalysisInfo;

typedef struct _MatchData_ {
    short Type;
    short SubType;
    short Status;
    va_t Addresses[2];
    short MatchRate;
    va_t UnpatchedParentAddress;
    va_t PatchedParentAddress;
} MatchData;

enum { NAME_MATCH, FINGERPRINT_MATCH, TWO_LEVEL_FINGERPRINT_MATCH, TREE_MATCH, FINGERPRINT_INSIDE_FUNCTION_MATCH, FUNCTION_MATCH };

typedef struct _AnalysisInfoList_ {
    PAnalysisInfo p_analysis_info;
    SOCKET socket;
    va_t address;
    struct _AnalysisInfoList_* prev;
    struct _AnalysisInfoList_* next;
} AnalysisInfoList;

typedef pair <va_t, PBasicBlock> AddrPBasicBlock_Pair;
typedef pair <va_t, string> AddrDisassembly_Pair;
typedef pair <unsigned char*, va_t> FingerPrintAddress_Pair;
typedef pair <string, va_t*> TwoLevelFingerPrintAddress_Pair;
typedef pair <va_t, unsigned char*> AddressFingerPrintAddress_Pair;
typedef pair <string, va_t> NameAddress_Pair;
typedef pair <va_t, string> AddressName_Pair;
typedef pair <va_t, PMapInfo> AddrPMapInfo_Pair;
typedef pair <va_t, MatchData> MatchMap_Pair;
typedef pair <unsigned char*, unsigned char*> Fingerprint_Pair;

#define STATUS_TREE_CHECKED 0x00000001
#define STATUS_MAPPING_DISABLED 0x2

#pragma pack(pop)
