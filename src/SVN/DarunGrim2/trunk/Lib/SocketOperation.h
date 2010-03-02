#pragma once
#pragma warning(disable:4200) 
#pragma pack(4)
#include <windows.h>

SOCKET CreateListener(DWORD (CALLBACK *WorkerThread)(LPVOID lpParam),unsigned short listening_port);
SOCKET ConnectToServer(char *hostname,unsigned short port);
HWND PutSocketToWSAAsyncSelect(SOCKET a_socket,LRESULT (CALLBACK *SocketMessageWndProc)(HWND wnd,UINT message,WPARAM wp,LPARAM lp),unsigned int wMsg);
