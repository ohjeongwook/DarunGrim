#pragma once

#include <unordered_set>
#include <unordered_map>

#pragma pack(push)
#pragma pack(1)
#include "Common.h"
#include "IDAAnalysisCommon.h"

using namespace std;
using namespace stdext;

//FingerPrintInfo
//Pushing Fingerprint Information
typedef struct _FingerPrintInfo_ {
	va_t addr;
} FingerPrintInfo,*PFingerPrintInfo;

typedef struct _FunctionMatchInfo_
{
	va_t TheSourceAddress;
	va_t EndAddress;
	va_t TheTargetAddress;
	short BlockType;
	short MatchRate;
	char *TheSourceFunctionName;
	short Type;
	char *TheTargetFunctionName;
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
	size_t operator() (/*[in]*/ const unsigned char *Bytes) const
	{
		size_t Key=0;
		for(int i=0;i<*(unsigned short *)Bytes;i++)
		{
			Key+=Bytes[sizeof(short)+i];
		}
		return  Key;
	}
public:
	bool operator() (/*[in]*/const unsigned char *Bytes01,/*[in]*/ const unsigned char *Bytes02) const
	{
		if( Bytes01==Bytes02 )
		{
			return 0;
		}

		if(*(unsigned short *)Bytes01==*(unsigned short *)Bytes02)
		{
			return (memcmp(Bytes01+sizeof(unsigned short),Bytes02+sizeof(unsigned short),*(unsigned short *)Bytes01)<0);
		}
		return (*(unsigned short *)Bytes01>*(unsigned short *)Bytes02);
	}
};

//,hash_compare<string,equ_str> 
typedef struct _AnalysisInfo_ {
	FileInfo file_info;
	multimap <va_t, PBasicBlock> address_map;
	multimap <va_t,string> address_disassembly_map;
	multimap <unsigned char *,va_t,hash_compare_fingerprint> fingerprint_map;
	multimap <va_t,unsigned char *> address_fingerprint_map;
	multimap <string, va_t> name_map;
	multimap <va_t,string> address_name_map;
	multimap <va_t, PMapInfo> map_info_map;
} AnalysisInfo,*PAnalysisInfo;

typedef struct _MatchData_{
	short Type;
	short SubType;
	short Status;
	va_t Addresses[2];
	short MatchRate;
	va_t UnpatchedParentAddress;
	va_t PatchedParentAddress;
} MatchData;

enum {NAME_MATCH,FINGERPRINT_MATCH,TWO_LEVEL_FINGERPRINT_MATCH,TREE_MATCH,FINGERPRINT_INSIDE_FUNCTION_MATCH,FUNCTION_MATCH};

typedef struct _AnalysisInfoList_ {
	PAnalysisInfo p_analysis_info;
	SOCKET socket;
	va_t address;
	struct _AnalysisInfoList_ *prev;
	struct _AnalysisInfoList_ *next;
} AnalysisInfoList;

typedef pair <va_t, PBasicBlock> AddrPBasicBlock_Pair;
typedef pair <va_t, string> AddrDisassembly_Pair;
typedef pair <unsigned char *, va_t> FingerPrintAddress_Pair;
typedef pair <string, va_t*> TwoLevelFingerPrintAddress_Pair;
typedef pair <va_t,unsigned char *> AddressFingerPrintAddress_Pair;
typedef pair <string, va_t> NameAddress_Pair;
typedef pair <va_t, string> AddressName_Pair;
typedef pair <va_t, PMapInfo> AddrPMapInfo_Pair;
typedef pair <va_t, MatchData> MatchMap_Pair;
typedef pair <unsigned char *,unsigned char *> Fingerprint_Pair;

#define STATUS_TREE_CHECKED 0x00000001
#define STATUS_MAPPING_DISABLED 0x2

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

#pragma pack(pop)
