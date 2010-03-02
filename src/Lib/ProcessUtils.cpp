#include <windows.h>
#include <stdio.h>

HANDLE ServerHandle=NULL;

bool StartProcess(LPTSTR szCmdline)
{
	//msg("%s: Entry\n",__FUNCTION__);

	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

	//msg("%s: Executing [%s] \n",__FUNCTION__,szCmdline);
	if(CreateProcess(
		NULL,
		szCmdline,      // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&StartupInfo,            // Pointer to STARTUPINFO structure
		&ProcessInformation)           // Pointer to PROCESS_INFORMATION structure
	)
	{
		ServerHandle=ProcessInformation.hProcess;
		//msg("%s: ServerHandle=%x\n",__FUNCTION__,ServerHandle);
		return TRUE;
	}
	if(1) //if server process is already up
	{
		//OpenProcess
		ServerHandle=OpenProcess(
			PROCESS_ALL_ACCESS,
			FALSE,
			10656);
		//msg("%s: ServerHandle=%x\n",__FUNCTION__,ServerHandle);
	}
	return FALSE;
}

void *malloc_wrapper(size_t size)
{
	if(ServerHandle)
	{
		return VirtualAllocEx(
			ServerHandle,
			NULL,
			size,
			MEM_COMMIT,
			PAGE_READWRITE);
	}else{
		return malloc(size);
	}
}

void *realloc(void *memblock,size_t old_size,size_t size)
{
	if(ServerHandle)
	{
		LPVOID ret_mem=VirtualAllocEx(
			ServerHandle,
			NULL,
			size,
			MEM_COMMIT,
			PAGE_READWRITE);
		if(memblock && old_size>0)
		{
			memcpy(ret_mem,memblock,old_size);
			VirtualFree(memblock,
				0, 
				MEM_RELEASE);
		}
		return ret_mem;
	}else{
		return realloc(memblock,size);
	}
}

char *WriteToTemporaryFile(const char *format,...)
{
#define BUFSIZE 512
	HANDLE hTempFile;
	char szTempName[BUFSIZE];  
	char lpPathBuffer[BUFSIZE];
	DWORD dwBufSize=BUFSIZE;
	DWORD dwRetVal;
	DWORD uRetVal;

	// Get the temp path.
	dwRetVal=GetTempPath(dwBufSize,	// length of the buffer
			lpPathBuffer); // buffer for path 
	if(dwRetVal > dwBufSize ||(dwRetVal==0))
	{
		printf("GetTempPath failed with error %d.\n",GetLastError());
		return NULL;
	}

	// Create a temporary file. 
	uRetVal=GetTempFileName(lpPathBuffer,// directory for tmp files
			"DarunGrim",		// temp file name prefix 
			0,			// create unique name 
			szTempName); // buffer for name 
	if(uRetVal==0)
	{
		printf("GetTempFileName failed with error %d.\n",
				GetLastError());
		return NULL;
	}

	// Create the new file to write the upper-case version to.
	hTempFile=CreateFile((LPTSTR)szTempName,// file name 
			GENERIC_READ | GENERIC_WRITE,// open r-w 
			0,					// do not share 
			NULL,				// default security 
			CREATE_ALWAYS,		// overwrite existing
			FILE_ATTRIBUTE_NORMAL,// normal file 
			NULL);				// no template 
	if(hTempFile==INVALID_HANDLE_VALUE) 
	{ 
		printf("CreateFile failed with error %d.\n",GetLastError());
		return NULL;
	} 

	va_list args;
	va_start(args,format);
	char Contents[1024]={0,};
	_vsnprintf(Contents,sizeof(Contents)/sizeof(char),format,args);
	va_end(args);

	DWORD dwBytesWritten;
	BOOL fSuccess=WriteFile(hTempFile,
		Contents,
		strlen(Contents),
		&dwBytesWritten,
		NULL); 
	if(!fSuccess) 
	{
		printf("WriteFile failed with error %d.\n",GetLastError());
		return NULL;
	}
	CloseHandle(hTempFile);
	return _strdup(szTempName);
}

void Execute(bool Wait,const char *format,...)
{
	STARTUPINFO StartupInfo;
	PROCESS_INFORMATION ProcessInformation;

    ZeroMemory(&StartupInfo,sizeof(StartupInfo));
    StartupInfo.cb=sizeof(StartupInfo);
    ZeroMemory(&ProcessInformation,sizeof(ProcessInformation));

	va_list args;
	va_start(args,format);
	char szCmdline[1024]={0,};
	_vsnprintf(szCmdline,sizeof(szCmdline)/sizeof(char),format,args);
	va_end(args);

	if(CreateProcess(
		NULL,
		szCmdline,      // Command line
		NULL,           // Process handle not inheritable
		NULL,           // Thread handle not inheritable
		FALSE,          // Set handle inheritance to FALSE
		0,              // No creation flags
		NULL,           // Use parent's environment block
		NULL,           // Use parent's starting directory 
		&StartupInfo,            // Pointer to STARTUPINFO structure
		&ProcessInformation)           // Pointer to PROCESS_INFORMATION structure
	)
	{
		if(Wait)
		{
			// Wait until child process exits.
			WaitForSingleObject(ProcessInformation.hProcess,INFINITE);
		}
		// Close process and thread handles. 
		CloseHandle(ProcessInformation.hProcess);
		CloseHandle(ProcessInformation.hThread);
	}
}

