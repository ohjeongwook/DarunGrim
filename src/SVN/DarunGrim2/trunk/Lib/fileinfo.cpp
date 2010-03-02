#include <windows.h>
#include <winver.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "md5.h"
#include "fileinfo.h"

char *GetVersionData(LPVOID pVersionBlock,char *EntryName)
{
	UINT cbTranslate=0;
	HRESULT hr;
	char *Result=NULL;

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *lpTranslate;

	// Read the list of languages and code pages.
	VerQueryValue(pVersionBlock,
				TEXT("\\VarFileInfo\\Translation"),
				(LPVOID*)&lpTranslate,
				&cbTranslate);

	// Read the file description for each language and code page.
	for( size_t i=0; i < (cbTranslate/sizeof(struct LANGANDCODEPAGE)); i++ )
	{
		char SubBlock[1024];
		hr=_snprintf(SubBlock,sizeof(SubBlock),
				TEXT("\\StringFileInfo\\%04x%04x\\%s"),
				lpTranslate[i].wLanguage,
				lpTranslate[i].wCodePage,
				EntryName);
		if (FAILED(hr))
		{
			// TODO: write error handler.
		}

		char *lpBuffer;
		UINT dwBytes=sizeof(lpBuffer);
		// Retrieve file description for language and code page "i". 
		VerQueryValue(pVersionBlock,
					SubBlock,
					(LPVOID *)&lpBuffer,
					&dwBytes);
		if((DWORD)lpBuffer==0xcccccccc)
		{
			lpBuffer=NULL;
		}
		if(lpBuffer)
			printf("%s\n",lpBuffer);
		Result=lpBuffer;
	}
	return Result;
}

char *GetFileVersionInfoStr(LPTSTR szFilename,char *InfoStr)
{
	DWORD dwSize=0;
	DWORD dwHandle=0;
	BOOL bVerGot=false;
	BOOL bVerQuery=false;
	LPVOID pVersionBlock;
	LPVOID lplpBuffer;
	UINT cbTranslate=0;
	char *RetStr=NULL;

	VS_FIXEDFILEINFO *vsInfo;
	dwSize=GetFileVersionInfoSize(szFilename,&dwHandle);
	if(dwSize>0)
	{
		pVersionBlock=(LPVOID)malloc(dwSize);
		if(pVersionBlock)
		{
			bVerGot=GetFileVersionInfo(szFilename,0,dwSize,pVersionBlock);
			//lplpBuffer=(LPVOID)malloc(dwSize);
			bVerQuery=VerQueryValue(pVersionBlock,TEXT("\\"),(LPVOID*)&vsInfo,&cbTranslate);
			DWORD dwFVMS=vsInfo->dwFileVersionMS;
			RetStr=strdup(GetVersionData(pVersionBlock,InfoStr));
			free(pVersionBlock);
		}
	}
	return RetStr;
}

// GetLastWriteTime - Retrieves the last-write time and converts
//                    the time to a string
//
// Return value - TRUE if successful,FALSE otherwise
// hFile      - Valid file handle
// lpszString - Pointer to buffer to receive string

char *GetLastWriteTime(LPCSTR filename)
{
    FILETIME ftCreate,ftAccess,ftWrite;
    SYSTEMTIME stUTC,stLocal;

	HANDLE hFile=CreateFile(filename,   // file to open
					GENERIC_READ,         // open for reading
					FILE_SHARE_READ|FILE_SHARE_WRITE,      // share for reading and writing
					NULL,                 // default security
					OPEN_EXISTING,        // existing file only
					FILE_ATTRIBUTE_NORMAL,// normal file
					NULL);                 // no attr. template
	 
	if (hFile==INVALID_HANDLE_VALUE) 
	{ 
		printf("Could not open file (error %d)\n",GetLastError());
		return NULL;
	}

    // Retrieve the file times for the file.
    if (!GetFileTime(hFile,&ftCreate,&ftAccess,&ftWrite))
        return NULL;
	CloseHandle(hFile);

    // Convert the last-write time to local time.
    FileTimeToSystemTime(&ftWrite,&stUTC);
    //SystemTimeToTzSpecificLocalTime(NULL,&stUTC,&stLocal);

	//ex) 2004-10-02 15:33:16
	char *buffer=(char *)malloc(1024);
	_snprintf(buffer,1024,TEXT("%d-%02d-%02d %02d:%02d:%02d"),
		stUTC.wYear,stUTC.wMonth,stUTC.wDay,
		stUTC.wHour,stUTC.wMinute,stUTC.wSecond);

    return buffer;
}

char *GetFileMD5Sum(LPCSTR filename)
{
	HANDLE hFile=CreateFile(filename,   // file to open
					GENERIC_READ,         // open for reading
					FILE_SHARE_READ|FILE_SHARE_WRITE,      // share for reading and writing
					NULL,                 // default security
					OPEN_EXISTING,        // existing file only
					FILE_ATTRIBUTE_NORMAL,// normal file
					NULL);                 // no attr. template
	 
	if (hFile==INVALID_HANDLE_VALUE) 
	{ 
		printf("Could not open file (error %d)\n",GetLastError());
		return NULL;
	}
	MD5_CTX mdContext;
	MD5Init(&mdContext);
	
	char inBuffer[1024];
	DWORD nBytesToRead=sizeof(inBuffer);
	DWORD nBytesRead;
	while(1)
	{
		bool bResult=ReadFile(hFile,
					&inBuffer,
					nBytesToRead,
					&nBytesRead,
					NULL) ; 

		if (bResult &&  nBytesRead==0) 
		{ 
			// This is the end of the file. 
			break;
		}
		MD5Update(&mdContext,(unsigned char *)inBuffer,nBytesRead);
	}
	CloseHandle(hFile);

	static unsigned char digest[16];
	MD5Final(digest,&mdContext);
	static char md5_str_buffer[16*2+1];
	memset(md5_str_buffer,0,sizeof(md5_str_buffer));
	for(int i=0;i<16;i++)
	{
		_snprintf(md5_str_buffer+i*2,3,"%.2x",digest[i]&0xff);
	}

	return &md5_str_buffer[0];
}

#ifdef TEST
int _tmain(int argc,_TCHAR* argv[])
{
	char *filename="C:\\WINNT\\system32\\msgsvc.dll";

	char *CompanyName=GetFileVersionInfoStr(filename,"CompanyName");
	char *FileVersion=GetFileVersionInfoStr(filename,"FileVersion");
	char *FileDescription=GetFileVersionInfoStr(filename,"FileDescription");
	char *InternalName=GetFileVersionInfoStr(filename,"InternalName");
	char *ProductName=GetFileVersionInfoStr(filename,"ProductName");
	printf("CompanyName=%s\n",CompanyName);
	printf("FileVersion=%s\n",FileVersion);
	printf("FileDescription=%s\n",FileDescription);
	printf("InternalName=%s\n",InternalName);
	printf("ProductName=%s\n",ProductName);
	free(CompanyName);
	free(FileVersion);
	free(FileDescription);
	free(InternalName);
	free(ProductName);

	char *DateTimeStr=GetLastWriteTime(filename);
	printf("%s\n",DateTimeStr);
	free(DateTimeStr);

	char *digest=GetFileMD5Sum(filename);
	printf("digest=%s\n",digest);
	return 0;
}

#endif