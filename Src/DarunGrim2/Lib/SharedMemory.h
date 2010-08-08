#pragma once
#pragma warning(disable:4200) 
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>

#pragma pack(4)

#include "TLV.h"
#define NULL_DATA 0xff


typedef struct _MemoryHeader_ {
	DWORD ReadPoint;
	DWORD WritePoint;
	DWORD BufferSize;
	BYTE Data[];
}  MemoryHeader,*PMemoryHeader ;


typedef struct _DataSharer_ {
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
	CRITICAL_SECTION critical_section;
#endif
	HANDLE EventHandleForReading;
	HANDLE EventHandleForWriting;
	HANDLE MapFileHandle;
	PMemoryHeader MemoryHeaderPtr;
} DataSharer,*PDataSharer;

BOOL InitDataSharer(PDataSharer p_data_sharer,TCHAR *SharedMemoryName,int SharedMemorySize,BOOL is_server);
BOOL PutData(PDataSharer p_data_sharer,BYTE type,PBYTE data,DWORD length);
PBYTE GetData(PDataSharer p_data_sharer,BYTE *p_type,DWORD *p_length);
int CheckForData(DataSharer *DataSharerPtr,int NumberOfDataSharer);
