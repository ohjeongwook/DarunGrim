#pragma once
#pragma pack(push)
#pragma pack(1)

#include "IDAAnalysisCommon.h"
#include <hash_set>
#include <hash_map>
using namespace std;
using namespace stdext;

//FingerPrintInfo
//Pushing Fingerprint Information
typedef struct _FingerPrintInfo_ {
	DWORD addr;
} FingerPrintInfo,*PFingerPrintInfo;

typedef struct _FunctionMatchInfo_
{
	DWORD TheSourceAddress;
	DWORD EndAddress;
	DWORD TheTargetAddress;
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
	DWORD StartAddress;
	DWORD EndAddress;
} CodeBlock;

enum {SEND_ANALYSIS_DATA,ADD_UNINDENTIFIED_ADDR,ADD_MATCH_ADDR,SHOW_DATA,SHOW_MATCH_ADDR,JUMP_TO_ADDR,GET_DISASM_LINES};


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
		for(int i=0;i<*(short *)Bytes;i++)
		{
			Key+=Bytes[sizeof(short)+i];
		}
		return  Key;
	}
public:
	bool operator() (/*[in]*/const unsigned char *Bytes01,/*[in]*/ const unsigned char *Bytes02) const
	{
		if(*(short *)Bytes01==*(short *)Bytes02)
		{
			return (memcmp(Bytes01+sizeof(short),Bytes02+sizeof(short),*(short *)Bytes01)<0);
		}
		return (*(short *)Bytes01>*(short *)Bytes02);
	}
};

//,hash_compare<string,equ_str> 
typedef struct _AnalysisInfo_ {
	FileInfo file_info;
	multimap <DWORD, POneLocationInfo> address_hash_map;
	multimap <DWORD,string> address_disassembly_hash_map;
	multimap <unsigned char *,DWORD,hash_compare_fingerprint> fingerprint_hash_map;
	multimap <DWORD,unsigned char *> address_fingerprint_hash_map;
	multimap <string, DWORD> name_hash_map;
	multimap <DWORD,string> address_name_hash_map;
	multimap <DWORD, PMapInfo> map_info_hash_map;
} AnalysisInfo,*PAnalysisInfo;

typedef struct _MatchData_{
	short Type;
	short SubType;
	short Status;
	DWORD Addresses[2];
	short MatchRate;
	DWORD UnpatchedParentAddress;
	DWORD PatchedParentAddress;
} MatchData;

enum {NAME_MATCH,FINGERPRINT_MATCH,TWO_LEVEL_FINGERPRINT_MATCH,TREE_MATCH,FINGERPRINT_INSIDE_FUNCTION_MATCH,FUNCTION_MATCH};

typedef struct _AnalysisInfoList_ {
	PAnalysisInfo p_analysis_info;
	SOCKET socket;
	DWORD address;
	struct _AnalysisInfoList_ *prev;
	struct _AnalysisInfoList_ *next;
} AnalysisInfoList;

typedef pair <DWORD, POneLocationInfo> AddrPOneLocationInfo_Pair;
typedef pair <DWORD, string> AddrDisassembly_Pair;
typedef pair <unsigned char *,DWORD> FingerPrintAddress_Pair;
typedef pair <string, DWORD*> TwoLevelFingerPrintAddress_Pair;
typedef pair <DWORD,unsigned char *> AddressFingerPrintAddress_Pair;
typedef pair <string, DWORD> NameAddress_Pair;
typedef pair <DWORD, string> AddressName_Pair;
typedef pair <DWORD, PMapInfo> AddrPMapInfo_Pair;
typedef pair <DWORD, MatchData> MatchMap_Pair;
typedef pair <unsigned char *,unsigned char *> Fingerprint_Pair;

#define STATUS_TREE_CHECKED 0x00000001
#define STATUS_MAPPING_DISABLED 0x2

#pragma pack(pop)
