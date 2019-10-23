#include <windows.h>
#include <winver.h>
#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "md5.h"
#include "fileinfo.h"

char* GetVersionData(LPVOID pVersionBlock, char* EntryName)
{
    UINT cbTranslate = 0;
    HRESULT hr;
    char* Result = NULL;

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
    for (size_t i = 0; i < (cbTranslate / sizeof(struct LANGANDCODEPAGE)); i++)
    {
        char SubBlock[1024];
        hr = _snprintf(SubBlock, 1024,
            TEXT("\\StringFileInfo\\%04x%04x\\%s"),
            lpTranslate[i].wLanguage,
            lpTranslate[i].wCodePage,
            EntryName);
        if (FAILED(hr))
        {
            // TODO: write error handler.
        }

        char* lpBuffer;
        UINT dwBytes = sizeof(lpBuffer);
        // Retrieve file description for language and code page "i". 
        VerQueryValue(pVersionBlock,
            SubBlock,
            (LPVOID*)&lpBuffer,
            &dwBytes);
        if ((DWORD)lpBuffer == 0xcccccccc)
        {
            lpBuffer = NULL;
        }
        if (lpBuffer)
            printf("%s\n", lpBuffer);
        Result = lpBuffer;
    }
    return Result;
}

char* GetFileVersionInfoStr(LPTSTR szFilename, char* InfoStr)
{
    DWORD dwSize = 0;
    DWORD dwHandle = 0;
    BOOL bVerGot = false;
    BOOL bVerQuery = false;
    LPVOID pVersionBlock;
    UINT cbTranslate = 0;
    char* RetStr = NULL;

    VS_FIXEDFILEINFO* vsInfo;
    dwSize = GetFileVersionInfoSize(szFilename, &dwHandle);
    if (dwSize > 0)
    {
        pVersionBlock = (LPVOID)malloc(dwSize);
        if (pVersionBlock)
        {
            bVerGot = GetFileVersionInfo(szFilename, 0, dwSize, pVersionBlock);
            //lplpBuffer=(LPVOID)malloc(dwSize);
            bVerQuery = VerQueryValue(pVersionBlock, TEXT("\\"), (LPVOID*)&vsInfo, &cbTranslate);
            DWORD dwFVMS = vsInfo->dwFileVersionMS;
            RetStr = strdup(GetVersionData(pVersionBlock, InfoStr));
            free(pVersionBlock);
        }
    }
    return RetStr;
}
