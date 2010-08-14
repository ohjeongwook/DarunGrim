#pragma once
#include <windows.h>
#include <tchar.h>
#include <stdarg.h>
#include <wtypes.h>

void PrintToDbg(const TCHAR *format,...);
/*
__inline void DebugPrintf(const TCHAR *format,...)
{
	TCHAR statement_buffer[1024]={0,};

	va_list args;
	va_start(args,format);
	_vsntprintf(statement_buffer,sizeof(statement_buffer)/sizeof(TCHAR),format,args);
	va_end(args);
	OutputDebugString(statement_buffer);
}*/

void __inline PrintToNone(const TCHAR *format,...)
{
}
void PrintToStdOutWithTime(const TCHAR *format,...);

HANDLE OpenLogFile(char *szTempName);
void WriteToLogFile(HANDLE hFile,const char *format,...);
void CloseLogFile(HANDLE hFile);
