#pragma once
#pragma warning(disable:4200) 
#pragma pack(4)
#include <windows.h>
#include "TLV.h"


BOOL SendTLVData(SOCKET client_socket,char type,PBYTE data,DWORD data_length);
PBYTE RecvTLVData(SOCKET client_socket,char *p_type,DWORD *p_length);

#define WM_SHARED_SOCKET_EVENT WM_USER + 50
void SetSharedSocketDataReceiver(int (*SharedSocketDataReceiver)(SOCKET data_socket,char type,DWORD length,PBYTE data));
LRESULT CALLBACK SharedSocketDataReceiverWndProc(HWND wnd,UINT message,WPARAM wp,LPARAM lp);