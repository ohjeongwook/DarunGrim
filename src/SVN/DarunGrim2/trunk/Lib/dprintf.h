#pragma once
#include <windows.h>
#include <tchar.h>

void PrintToDbg(const TCHAR *format,...);
void __inline PrintToNone(const TCHAR *format,...)
{
}
void PrintToStdOutWithTime(const TCHAR *format,...);

HANDLE OpenLogFile(char *szTempName);
void WriteToLogFile(HANDLE hFile,const char *format,...);
void CloseLogFile(HANDLE hFile);
