#pragma once
#pragma warning (disable : 4819)

#ifndef IDA_HEADER_INCLUDED
#define IDA_HEADER_INCLUDED
#include <ida.hpp>
#include <idp.hpp>
#include <expr.hpp>
#include <bytes.hpp>
#include <graph.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <xref.hpp>
#include <intel.hpp>
#include <struct.hpp>
#endif

#include <map>
#include <hash_map>
#include <queue>
#include <list>
#include <string>
#include <iostream>
#include <hash_set>
using namespace std;
using namespace stdext;

enum{TYPE_CURRENT_ADDRESS,TYPE_FUNCTION_NAME,TYPE_MAP_DATA,TYPE_DISASSEMBLY,TYPE_END};

typedef struct _AddressMap_
{
	hash_map <int,ea_t> number2address_map;
	hash_map <ea_t,int> address2number_map;
	multimap <int,int> number_map;
} AddressMap;


enum {TRACE_TYPE_START,TRACE_TYPE_LOOP,TRACE_TYPE_DISASM_LINE,TRACE_TYPE_END};
typedef struct _TraceMessage_{
	int type;
	int level;
	ea_t current_address;
	int disasm_line_len;
	char disasm_line[];
} TraceMessage;

int get_current_operand_pos();
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void DumpToFile(int type,int level,ea_t parent_ea,char *disasm_line);
void DumpPlainDataToScreen(int type,int level,ea_t current_address,char *disasm_line);
void DumpMapDataToScreen(char type,PBYTE data,int length);
void DumpPlainData(ea_t root_ea,multimap <ea_t,ea_t> *p_trace_result_map,void (*Callback)(int type,int level,ea_t parent_ea,char *disasm_line));
multimap <ea_t,ea_t> *TraceVariable(ea_t start_address,op_t operand,bool b_trace_up,bool b_trace_passive_usage);
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void DumpMapDataToSharedSocket(char type,PBYTE data,int length);
void DumpMapDataToCOMServer(char type,PBYTE data,int length);
void DumpMapData(HANDLE hFile,ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map,void (*Callback)(char type,PBYTE data,int length));
void DumpMapDataByFilename(char *filename,ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map,void (*Callback)(char type,PBYTE data,int length));
void DumpRoots(HANDLE hFile,ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map);