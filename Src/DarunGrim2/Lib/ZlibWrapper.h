#pragma once
#include <assert.h>
#include "zlib.h"

class ZlibWrapper
{
private:
	#define CHUNK 16384*10
	z_stream strm;
	HANDLE hInFile;
	DWORD dwInFileLength;
	DWORD dwInFileOffset;
	HANDLE hOutFile;
	BOOL bCompress;
	unsigned char *InBuffer;
	DWORD InBufferLength;
	DWORD InBufferSize;
	DWORD InBufferOffset;
	unsigned char *TmpInBuffer;
public:
	ZlibWrapper(BOOL b_compress,int level=9)
	{
		hOutFile=INVALID_HANDLE_VALUE;
		hInFile=INVALID_HANDLE_VALUE;
		bCompress=b_compress;
		dwInFileLength=0;
		dwInFileOffset=0;
		int ret;
		/* allocate deflate state */
		strm.zalloc=Z_NULL;
		strm.zfree=Z_NULL;
		strm.opaque=Z_NULL;
		strm.avail_in=0;
		strm.next_in=Z_NULL;
		InBuffer=NULL;
		InBufferLength=0;
		InBufferSize=0;
		InBufferOffset=0;
		TmpInBuffer=(unsigned char *)malloc(CHUNK);
		if(bCompress)
		{
			ret=deflateInit(&strm,level);
		}else
		{
			ret=inflateInit(&strm);
		}
		if(ret!=Z_OK)
			return;
	}

	~ZlibWrapper()
	{
		if(hOutFile!=INVALID_HANDLE_VALUE)
		{
			WriteData((unsigned char *)"",0);
		}
		if(bCompress)
			(void)deflateEnd(&strm);
		else
			(void)inflateEnd(&strm);
		if(hOutFile!=INVALID_HANDLE_VALUE)
		{
			CloseHandle(hOutFile);
		}
		if(hInFile!=INVALID_HANDLE_VALUE)
		{
			CloseHandle(hInFile);
		}
		if(TmpInBuffer)
			free(TmpInBuffer);
	}

	int SetOutFile(char *Filename,DWORD Offset=0L,DWORD dwMoveMethod=FILE_BEGIN)
	{
		hOutFile=CreateFile(Filename, // file to create
			GENERIC_WRITE, // open for writing
			0, // do not share
			NULL, // default security
			(dwMoveMethod==FILE_BEGIN && Offset==0L)?CREATE_ALWAYS:OPEN_EXISTING, 
			FILE_ATTRIBUTE_NORMAL | // normal file
			NULL, // asynchronous I/O
			NULL); // no attr. template
		if(hOutFile==INVALID_HANDLE_VALUE) 
		{ 
			printf("Could not open file %s (error %d)\n", Filename,GetLastError());
			return -1;
		}
		SetFilePointer(hOutFile,Offset,0L,dwMoveMethod);
		return 0;
	}

	int SetInFile(char *Filename,DWORD Offset=0L,DWORD Length=0L,DWORD dwMoveMethod=FILE_BEGIN)
	{
		printf("Filename=%s\n",Filename);
		hInFile=CreateFile(Filename,    // file to open
			GENERIC_READ,          // open for reading
			FILE_SHARE_READ,       // share for reading
			NULL,                  // default security
			OPEN_EXISTING,         // existing file only
			FILE_ATTRIBUTE_NORMAL, // normal file
			NULL);                 // no attr. template
		if(hInFile==INVALID_HANDLE_VALUE) 
		{ 
			printf("Could not open file %s (error %d)\n",Filename,GetLastError());
			return FALSE;
		}
		SetFilePointer(hInFile,Offset,0L,dwMoveMethod);
		dwInFileLength=Length;

		InBuffer=NULL;
		InBufferLength=0;
		InBufferSize=0;
		InBufferOffset=0;
		return TRUE;
	}

	DWORD Write()
	{
		DWORD ret=0;
		while(1)
		{
			if(dwInFileLength>0L && dwInFileLength<=dwInFileOffset)
				break;
			DWORD dwBytesRead;
			BOOL status=ReadFile(hInFile, 
				TmpInBuffer, 
				CHUNK,
				&dwBytesRead,
				NULL);
			if(!status) 
			{
				break;
			}
			dwInFileOffset+=dwBytesRead;
			ret+=dwBytesRead;
			WriteData(TmpInBuffer,dwBytesRead);
			if(dwBytesRead<=0)
			{
				break;
			}
		}
		CloseHandle(hInFile);
		return ret;
	}

	int WriteData( unsigned char *in, DWORD dwBytesRead )
	{
		unsigned char out[CHUNK];
		int flush=dwBytesRead==0?Z_FINISH:Z_NO_FLUSH;
		strm.next_in=in;
		strm.avail_in=dwBytesRead;
		do 
		{
			strm.avail_out=CHUNK;
			strm.next_out=out;
			int ret;
			if(bCompress)
				ret=deflate(&strm,flush);	/* no bad return value */
			else
			{
				ret=inflate(&strm,Z_NO_FLUSH);
				assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
				switch(ret) 
				{
					case Z_NEED_DICT:
						ret=Z_DATA_ERROR;	/* and fall through */
					case Z_DATA_ERROR:
					case Z_MEM_ERROR:
						(void)inflateEnd(&strm);
						return FALSE;
				}
			}
			assert(ret!=Z_STREAM_ERROR);  /* state not clobbered */
			DWORD have=CHUNK-strm.avail_out;
			if(have>0)
			{
				DWORD dwBytesWritten;
				BOOL status=WriteFile(hOutFile,
					out,
					have,
					&dwBytesWritten, 
					NULL); 
				if(!status || dwBytesWritten!=have)
				{
					if(bCompress)
						(void)deflateEnd(&strm);
					else
						(void)inflateEnd(&strm);
					return FALSE;
				}
			}
		}while(strm.avail_out==0);
		assert(strm.avail_in==0);
		return TRUE;
	}

	DWORD ReadData( unsigned char *buffer, DWORD dwLength )
	{
		if(
			(InBufferLength>InBufferOffset) &&
			(InBufferLength-InBufferOffset)>=dwLength
		)
		{
			//printf("Copying buffer=0x%p,InBuffer(0x%p)+InBufferOffset(%d)=0x%p,dwLength=%d\n",buffer,InBuffer,InBufferOffset,InBuffer+InBufferOffset,dwLength);
			memcpy(buffer,InBuffer+InBufferOffset,dwLength);
			InBufferOffset+=dwLength;
			return dwLength;
		}
		if(dwInFileLength>0L && dwInFileLength<=dwInFileOffset)
			return 0;

		//while(1)
		{
			//In
			DWORD dwBytesToRead=CHUNK;
			if(dwInFileLength>0L && (dwInFileLength-dwInFileOffset)<CHUNK)
				dwBytesToRead=dwInFileLength-dwInFileOffset;
			
			if(dwBytesToRead<=0)
			{
				return 0;
			}

			DWORD dwBytesRead;
			BOOL status=ReadFile(hInFile, 
		        TmpInBuffer, 
				dwBytesToRead,
				&dwBytesRead,
				NULL);
			if(!status) 
			{
				return -1;
			}
			dwInFileOffset+=dwBytesRead;

			strm.next_in=TmpInBuffer;
			strm.avail_in=dwBytesRead;

			do
			{
				//Out
				unsigned char out[CHUNK];
				strm.avail_out=CHUNK;
				strm.next_out=out;
	
				//Perform compress/decompress
				int ret;
				if(bCompress)
					ret=deflate(&strm,Z_NO_FLUSH);	/* no bad return value */
				else
				{
					ret=inflate(&strm,Z_NO_FLUSH);
					assert(ret != Z_STREAM_ERROR);  /* state not clobbered */
					switch(ret) 
					{
						case Z_NEED_DICT:
							ret=Z_DATA_ERROR;	/* and fall through */
						case Z_DATA_ERROR:
						case Z_MEM_ERROR:
						case Z_STREAM_ERROR:
							(void)inflateEnd(&strm);
							return -1;
					}
				}
				assert(ret!=Z_STREAM_ERROR);  /* state not clobbered */
				//Buffering
				DWORD OutputLength=CHUNK-strm.avail_out;
				if(OutputLength>0)
				{
					DWORD RemainingDataLength=InBufferLength-InBufferOffset;
					InBufferLength=RemainingDataLength+OutputLength;
					unsigned char *OldInBuffer=InBuffer;
					if(InBufferSize<InBufferLength)
					{
						InBufferSize=InBufferLength*3;
						InBuffer=(unsigned char *)malloc(InBufferSize);
					}
					if(RemainingDataLength>0)
						memcpy(InBuffer,OldInBuffer+InBufferOffset,RemainingDataLength);
					InBufferOffset=0;
					if(OldInBuffer!=InBuffer && OldInBuffer)
						free(OldInBuffer);
					memcpy(InBuffer+RemainingDataLength,out,OutputLength);
				}
			}while(strm.avail_out==0);

			if(InBufferLength>=dwLength)
			{
				memcpy(buffer,InBuffer+InBufferOffset,dwLength);
				InBufferOffset+=dwLength;
				return dwLength;
			}
		}
		return -1;
	}
};
