#pragma once
#include <windows.h>
#include <stdarg.h>
#include <wtypes.h>

void dprintf(const TCHAR *format,...);
void __inline PrintToNone(const TCHAR *format,...)
{
}
void dprintf(const TCHAR *format,...);

HANDLE OpenLogFile(const char *szTempName);
void WriteToLogFile(HANDLE hFile,const char *format,...);
void CloseLogFile(HANDLE hFile);
