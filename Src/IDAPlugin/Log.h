#pragma once
#include <windows.h>
#include <stdarg.h>
#include <wtypes.h>

void SetLogLevel(int level);
void LogMessage(int level, const char *function_name, const TCHAR *format, ...);


void __inline dprintf_null(int level, const char *function_name, const TCHAR *format, ...)
{
}

HANDLE OpenLogFile(const char *szTempName);
void WriteToLogFile(HANDLE hFile, const char *format, ...);
void CloseLogFile(HANDLE hFile);
