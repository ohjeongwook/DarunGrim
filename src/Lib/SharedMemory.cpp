#pragma warning(disable:4189)
#pragma warning(disable:4127)
#pragma warning(disable:4996)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <malloc.h>
#include <tchar.h>
#include "SharedMemory.h"
#include "dprintf.h"

#define DEBUG_LEVEL 0

#ifndef dprintf
void dprintf(TCHAR *format, ...)
{
	va_list args;
	va_start(args,format);
	TCHAR buffer[1024*3]={0,};
	_vsntprintf(buffer,sizeof(buffer),format,args);
	va_end(args);
#if DEBUG_LEVEL > 0	
	printf(buffer);
	OutputDebugString(buffer);
#endif
}
#endif

BOOL PutData(
	PDataSharer p_data_sharer,
	BYTE type,
	PBYTE data,
	DWORD length)
{
	DWORD buffer_length;
	PTLV p_tlv=NULL;
	BOOL read_pending=FALSE;
	DWORD length_to_boundary=0;
	DWORD real_writer_point;
	DWORD real_writable_size;

#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
	EnterCriticalSection(&p_data_sharer->critical_section); 
#endif
	if(!p_data_sharer || !p_data_sharer->MemoryHeaderPtr)
	{
		return FALSE;
	}

	//needed bytes
	buffer_length=sizeof(TLV)+length;
	while(p_data_sharer->MemoryHeaderPtr->BufferSize
		<=
		p_data_sharer->MemoryHeaderPtr->WritePoint+buffer_length-p_data_sharer->MemoryHeaderPtr->ReadPoint
	)
	{
		//lack buffer to write
		//Wait For Read Event
#if DEBUG_LEVEL > 1 
		//too small buffer
		dprintf(TEXT("%s: Wait For Read Event(1) BufferSize=%d WritePoint=%d buffer_length=%d ReadPoint=%d\n"),
			__FUNCTION__,
			p_data_sharer->MemoryHeaderPtr->BufferSize,
			p_data_sharer->MemoryHeaderPtr->WritePoint,
			buffer_length,
			p_data_sharer->MemoryHeaderPtr->ReadPoint
			);
#endif		
		if(WaitForSingleObject(p_data_sharer->EventHandleForWriting,INFINITE)==WAIT_OBJECT_0) 
		{
			ResetEvent(p_data_sharer->EventHandleForWriting);
			continue;
		}
#if DEBUG_LEVEL > 1 
		//too small buffer
		dprintf(TEXT("%s: Got it\n"),
				__FUNCTION__);
#endif				
	}

	real_writer_point=p_data_sharer->MemoryHeaderPtr->WritePoint%p_data_sharer->MemoryHeaderPtr->BufferSize;
	real_writable_size=p_data_sharer->MemoryHeaderPtr->BufferSize-real_writer_point;
	if(real_writable_size<buffer_length)
	{
#if DEBUG_LEVEL > 1 
		//too small buffer
		dprintf(TEXT("%s: WritePoint %d -> %d\n"),
				__FUNCTION__,
				p_data_sharer->MemoryHeaderPtr->WritePoint,
				p_data_sharer->MemoryHeaderPtr->WritePoint+real_writable_size);
#endif
		memset(p_data_sharer->MemoryHeaderPtr->Data+real_writer_point,NULL_DATA,real_writable_size);
		//fill it with null and wait again
		p_data_sharer->MemoryHeaderPtr->WritePoint+=real_writable_size;
		real_writer_point=0;
	}

	while(p_data_sharer->MemoryHeaderPtr->BufferSize<=p_data_sharer->MemoryHeaderPtr->WritePoint+buffer_length-p_data_sharer->MemoryHeaderPtr->ReadPoint)
	{
		//lack buffer to write
		//Wait For Read Event
#if DEBUG_LEVEL > 1 
		dprintf(TEXT("%s: Wait For Read Event\n"),
				__FUNCTION__);
#endif		
		if(WaitForSingleObject(p_data_sharer->EventHandleForWriting,INFINITE)==WAIT_OBJECT_0)
		{
			ResetEvent(p_data_sharer->EventHandleForWriting);
			continue;
		}
#if DEBUG_LEVEL > 1 
		dprintf(TEXT("%s: Got it\n"),
				__FUNCTION__);
#endif		
		
	}
#if DEBUG_LEVEL > 3
	dprintf(TEXT("%s: BufferSize:%d<WP:%d+buffer_length:%d-RP=%d"),
		__FUNCTION__,
		p_data_sharer->MemoryHeaderPtr->BufferSize,p_data_sharer->MemoryHeaderPtr->WritePoint,buffer_length,p_data_sharer->MemoryHeaderPtr->ReadPoint);
	dprintf(TEXT("%s: real_writer_point=%d\n"),
		__FUNCTION__,
		real_writer_point);
#endif
	//just copy and increase WritePoint
	p_tlv=(PTLV)(p_data_sharer->MemoryHeaderPtr->Data+real_writer_point);
	p_tlv->Type=type;
	p_tlv->Length=length;
	if(data && length>0)
		memcpy(p_tlv->Data,data,length);
#if DEBUG_LEVEL > 2
	dprintf(TEXT("%s: W=%d/R=%d type=%d length=%d(length=%d)\n"),
		__FUNCTION__,
		p_data_sharer->MemoryHeaderPtr->WritePoint,
		p_data_sharer->MemoryHeaderPtr->ReadPoint,
		p_tlv->Type,
		p_tlv->Length,
		length);
#endif
	p_data_sharer->MemoryHeaderPtr->WritePoint+=buffer_length;
	//Set Read Event: For the case when the buffer is full
	SetEvent(p_data_sharer->EventHandleForReading);
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
	LeaveCriticalSection(&p_data_sharer->critical_section);
#endif
	return TRUE;
}

PBYTE GetData(PDataSharer p_data_sharer,BYTE *p_type,DWORD *p_length)
{
	PTLV p_tlv;
	DWORD readable_buffer_size;
	DWORD real_readable_buffer_size;
	DWORD real_read_point;

	if(!p_data_sharer->MemoryHeaderPtr)
	{
		if(p_type)
			*p_type=0;
		if(p_length)
			*p_length=0;
		return NULL;
	}
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
	EnterCriticalSection(&p_data_sharer->critical_section); 
#endif
#ifdef NON_BLOCKING_SHARED_MEMORY
	if(1)
#else
	while(1)
#endif
	{
		dprintf(TEXT("RP:%d WP: %d\n"),
			p_data_sharer->MemoryHeaderPtr->ReadPoint,
			p_data_sharer->MemoryHeaderPtr->WritePoint);
		while(p_data_sharer->MemoryHeaderPtr->ReadPoint==p_data_sharer->MemoryHeaderPtr->WritePoint)
		{
			//Wait For Read Event
			dprintf(TEXT("WaitForSingleObject\n"));
			if(WaitForSingleObject(p_data_sharer->EventHandleForReading,INFINITE)==WAIT_OBJECT_0)
			{
				ResetEvent(p_data_sharer->EventHandleForReading);
				continue;
			}
#ifdef NON_BLOCKING_SHARED_MEMORY
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
			LeaveCriticalSection(&p_data_sharer->critical_section); 
#endif
			return NULL;
#endif
		}

		real_read_point=p_data_sharer->MemoryHeaderPtr->ReadPoint%p_data_sharer->MemoryHeaderPtr->BufferSize;
		real_readable_buffer_size=p_data_sharer->MemoryHeaderPtr->BufferSize-real_read_point;
		//Read
		readable_buffer_size=p_data_sharer->MemoryHeaderPtr->WritePoint-p_data_sharer->MemoryHeaderPtr->ReadPoint;
		dprintf(TEXT("Real RP: %d Size: %d readable_buffer_size: %d\n"),real_read_point,real_readable_buffer_size,readable_buffer_size);
		if(readable_buffer_size>0 && real_readable_buffer_size>0)
		{
			if(p_data_sharer->MemoryHeaderPtr->Data[real_read_point]==NULL_DATA)
			{
#if DEBUG_LEVEL > 2
				dprintf(TEXT("%s: got NULL moving ReadPoint %d -> %d\n"),
						__FUNCTION__,
						p_data_sharer->MemoryHeaderPtr->ReadPoint,
						p_data_sharer->MemoryHeaderPtr->ReadPoint+real_readable_buffer_size);
#endif
				//null data
				//put ReadPoint to the boundary start
				p_data_sharer->MemoryHeaderPtr->ReadPoint+=real_readable_buffer_size;
				//make real_read_point 0
				real_read_point=0;

				//re-calculate
				real_readable_buffer_size=p_data_sharer->MemoryHeaderPtr->BufferSize-real_read_point;
				readable_buffer_size=p_data_sharer->MemoryHeaderPtr->WritePoint-p_data_sharer->MemoryHeaderPtr->ReadPoint;
			}
		}
		if(readable_buffer_size>sizeof(TLV))
		{
			DWORD current_block_length;
			p_tlv=(PTLV)(p_data_sharer->MemoryHeaderPtr->Data+p_data_sharer->MemoryHeaderPtr->ReadPoint%p_data_sharer->MemoryHeaderPtr->BufferSize);
			current_block_length=p_tlv->Length+sizeof(TLV);

#if DEBUG_LEVEL > 2
			dprintf(TEXT("%s: R=%d/W=%d p_tlv->Length=%d current_block_length=%d readable_buffer_size=%d\n"),
				__FUNCTION__,
				p_data_sharer->MemoryHeaderPtr->ReadPoint,
				p_data_sharer->MemoryHeaderPtr->WritePoint,
				p_tlv->Length,
				current_block_length,
				readable_buffer_size);
#endif

			if(current_block_length<=readable_buffer_size)
			{
#if DEBUG_LEVEL > 3
				dprintf(TEXT("%s: p_tlv->Length=%d\n"),
					__FUNCTION__,
					p_tlv->Length);
#endif
				if(p_tlv->Length>200000)
				{
#if DEBUG_LEVEL > 3
					dprintf(TEXT("%s: p_tlv->Length=%d\n"),
						__FUNCTION__,
						p_tlv->Length);
					dprintf(TEXT("%s: R=%d/W=%d p_tlv->Length=%d current_block_length=%d readable_buffer_size=%d\n"),
						__FUNCTION__,
						p_data_sharer->MemoryHeaderPtr->ReadPoint,
						p_data_sharer->MemoryHeaderPtr->WritePoint,
						p_tlv->Length,
						current_block_length,
						readable_buffer_size);
#endif
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
					LeaveCriticalSection(&p_data_sharer->critical_section);
#endif
					return NULL;
				}
				//p_tlv->Type,p_tlv->Length,p_tlv->Data
				PBYTE data_buffer=(PBYTE)malloc(p_tlv->Length);
				*p_type=p_tlv->Type;
				*p_length=p_tlv->Length;
				memcpy(data_buffer,p_tlv->Data,p_tlv->Length);
				//Increase ReadPoint
				p_data_sharer->MemoryHeaderPtr->ReadPoint+=current_block_length;
				//Set Write Event: For the case when the buffer is full
				SetEvent(p_data_sharer->EventHandleForWriting);
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
				LeaveCriticalSection(&p_data_sharer->critical_section);
#endif
				return data_buffer;
			}
		}
	}
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
	LeaveCriticalSection(&p_data_sharer->critical_section);
#endif
	return NULL;
}

BOOL InitDataSharer(PDataSharer p_data_sharer,TCHAR *SharedMemoryName,int SharedMemorySize,BOOL is_server)
{
	HANDLE MapFileHandle=INVALID_HANDLE_VALUE;
	PBYTE shared_buffer;
#define READ_EVENT_POSTIFX TEXT("_read")
#define WRITE_EVENT_POSTIFX TEXT("_write")
	int event_name_len=(_tcslen(SharedMemoryName)+max(_tcslen(READ_EVENT_POSTIFX),_tcslen(WRITE_EVENT_POSTIFX))+10)*sizeof(TCHAR);
	char *event_name=(char *)malloc(event_name_len);
	memset(event_name,0,event_name_len);
#ifdef UNICODE
	_snprintf(event_name,event_name_len/sizeof(TCHAR)-1,"%ws%ws",SharedMemoryName,READ_EVENT_POSTIFX);
#else
	_snprintf(event_name,event_name_len-1,"%s%s",SharedMemoryName,READ_EVENT_POSTIFX);
#endif
	dprintf("%s: Creating Event[%s]\n",__FUNCTION__,event_name);
	//Init R/W Event
	if(1 || is_server)
	{
		p_data_sharer->EventHandleForReading=CreateEventA(NULL,TRUE,FALSE,(LPCSTR)event_name);
	}else
	{
		p_data_sharer->EventHandleForReading=OpenEventA(EVENT_ALL_ACCESS,TRUE,(LPCSTR)event_name);
	}

	if (!p_data_sharer->EventHandleForReading) 
	{
		//error
		dprintf("%s: Creating Event Failed\n",__FUNCTION__);
		return FALSE;
	}

	memset(event_name,0,event_name_len);
#ifdef UNICODE
	_snprintf(event_name,(event_name_len)/sizeof(TCHAR)-1,"%ws%ws",SharedMemoryName,WRITE_EVENT_POSTIFX);
#else
	_snprintf(event_name,event_name_len-1,"%s%s",SharedMemoryName,WRITE_EVENT_POSTIFX);	
#endif
	dprintf("Creating Event[%s]\n",event_name);
	if(1 || is_server)
	{
		p_data_sharer->EventHandleForWriting= CreateEventA(NULL,TRUE,FALSE,(LPCSTR)event_name);
	}else
	{
		p_data_sharer->EventHandleForWriting=OpenEventA(EVENT_ALL_ACCESS,TRUE,(LPCSTR)event_name);
	}

	free(event_name);
	if (!p_data_sharer->EventHandleForWriting) 
	{ 
		//error
		dprintf("%s: Creating Event Failed\n",__FUNCTION__);
		return FALSE;
	}

	if(!is_server)
	{
		//Creates Map
		MapFileHandle=OpenFileMappingA(
			FILE_MAP_ALL_ACCESS,	// read/write access
			FALSE,					// do not inherit the name
			(LPCSTR)SharedMemoryName);	// name of mapping object
	}
	if(MapFileHandle==INVALID_HANDLE_VALUE || !MapFileHandle)
	{
		//Creates Map
		MapFileHandle=CreateFileMappingA(
			INVALID_HANDLE_VALUE,
			NULL,
			PAGE_READWRITE,
			0,
			SharedMemorySize+sizeof(MemoryHeader),
			(LPCSTR)SharedMemoryName);
	}

	if (MapFileHandle!=INVALID_HANDLE_VALUE && MapFileHandle)  
	{
		dprintf(TEXT("%s: Created Shared Memory[%s]\n"),__FUNCTION__,SharedMemoryName);
	
		shared_buffer=(PBYTE)MapViewOfFile(
			MapFileHandle,
			FILE_MAP_ALL_ACCESS,	// read/write permission
			0,
			0,
			SharedMemorySize+sizeof(MemoryHeader)); 

		if(shared_buffer)
		{
			dprintf(TEXT("%s: shared_buffer=%x\n"),
				__FUNCTION__,
				shared_buffer);
		
			//Init Shared Memory Header(R/W Pointer,Size)
			p_data_sharer->MemoryHeaderPtr=(PMemoryHeader)shared_buffer;
			if(is_server && p_data_sharer->MemoryHeaderPtr)
			{
				p_data_sharer->MemoryHeaderPtr->BufferSize=SharedMemorySize;
				p_data_sharer->MemoryHeaderPtr->ReadPoint=p_data_sharer->MemoryHeaderPtr->WritePoint=0;
			}
			dprintf(TEXT("%s: p_data_sharer->MemoryHeaderPtr->Data=%x\n"),
				__FUNCTION__,
				p_data_sharer->MemoryHeaderPtr->Data);
#ifndef USE_SINGLE_THREAD_FOR_SHARED_MEMORY
			InitializeCriticalSection(&p_data_sharer->critical_section);
#endif
			return TRUE;
		}
	}
	dprintf("%s: Returning False\n",__FUNCTION__);
	return FALSE;	
}

int CheckForData(DataSharer *DataSharerPtr,int NumberOfDataSharer)
{
	HANDLE *lpHandles=(HANDLE *)malloc(sizeof(HANDLE)*NumberOfDataSharer);
	for(int i=0;i<NumberOfDataSharer;i++)
	{
		lpHandles[i]=DataSharerPtr[i].EventHandleForReading;
	}
	DWORD RetVal=WaitForMultipleObjects(NumberOfDataSharer,lpHandles,FALSE,INFINITE);
	if(WAIT_OBJECT_0<=RetVal && RetVal<WAIT_OBJECT_0+NumberOfDataSharer)
	{
		printf("(RetVal-WAIT_OBJECT_0)=%d\n",RetVal-WAIT_OBJECT_0);
		ResetEvent(DataSharerPtr[RetVal-WAIT_OBJECT_0].EventHandleForWriting);
		return (int)(RetVal-WAIT_OBJECT_0);
	}
	return -1;
}
