#pragma warning (disable: 4819)
#pragma warning (disable: 4996)
#pragma warning (disable : 4786)
#pragma once

char *GetFileVersionInfoStr(LPTSTR szFilename,char *InfoStr);
char *GetLastWriteTime(LPCSTR filename);
char *GetFileMD5Sum(LPCSTR filename);

