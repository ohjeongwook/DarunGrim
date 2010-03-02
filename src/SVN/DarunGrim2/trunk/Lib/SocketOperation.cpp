#pragma warning(disable:4996)
#include <stdio.h>
#include "SocketOperation.h"

SOCKET CreateListener(DWORD (CALLBACK *WorkerThread)(LPVOID lpParam),unsigned short listening_port)
{
	//unsigned short listening_port=(unsigned short)lpParam;

	// Initialize Winsock
	WSADATA wsaData;
	int result=WSAStartup(MAKEWORD(2,2), &wsaData);
	if (result!= NO_ERROR)
	{
		printf("Error at WSAStartup()\n");
		return FALSE;
	}

	// Create a SOCKET for listening to client
	SOCKET a_socket;
	a_socket=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (a_socket==INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return FALSE;
	}

	sockaddr_in service;
	service.sin_family=AF_INET;
	service.sin_addr.s_addr=inet_addr("127.0.0.1");
	service.sin_port=htons(listening_port);

	if(bind(a_socket, 
		(SOCKADDR*)&service, 
		sizeof(service))==SOCKET_ERROR)
	{
		printf("bind() failed.\r\n");
		closesocket(a_socket);
		WSACleanup();
		return FALSE;
	}

	if(listen(a_socket,1)==SOCKET_ERROR)
	{
		printf("Error listening on socket.\r\n");
		closesocket(a_socket);
		WSACleanup();
		return FALSE;
	}
	SOCKET client_socket;
	printf("Waiting for client to connect on port %d...\r\n",listening_port);

	if(WorkerThread)
	{
		// Accept the connection.
		while(1)
		{
			client_socket=accept(a_socket,NULL,NULL);
			printf("accepting=%d\n",client_socket);			
			if(client_socket==INVALID_SOCKET)
			{
				int error=WSAGetLastError();
				printf("Socket error=%d\n",error);
				if(error!=WSAEWOULDBLOCK)
					break;
			}else{
				CreateThread(
					NULL,
					0,
					WorkerThread,
					(void*)client_socket,
					0,
					NULL);
			}
		}
		return INVALID_SOCKET;
	}else
	{
		return a_socket;
	}
}

SOCKET ConnectToServer(char *hostname,unsigned short port)
{
	// Create a SOCKET for connecting to server
	SOCKET a_socket=INVALID_SOCKET;
	WSADATA wsaData;
	int result=WSAStartup(MAKEWORD(2,2),&wsaData);
	if(result!= NO_ERROR)
	{
		printf("Error at WSAStartup()\n");
		return INVALID_SOCKET;
	}

	a_socket= socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (a_socket==INVALID_SOCKET) {
		printf("Error at socket(): %ld\n", WSAGetLastError());
		WSACleanup();
		return INVALID_SOCKET;
	}
	// The sockaddr_in structure specifies the address family,
	// IP address, and port of the server to be connected to.
	sockaddr_in clientService; 
	clientService.sin_family=AF_INET;
	clientService.sin_addr.s_addr=inet_addr(hostname);
	clientService.sin_port=htons(port);

	// Connect to server.
	if(connect(
		a_socket,
		(SOCKADDR*) &clientService,
		sizeof(clientService) 
	)==SOCKET_ERROR)
	{
		printf( "Failed to connect.\n" );
		WSACleanup();
		return INVALID_SOCKET;
	}

	u_long tru=1;
	ioctlsocket(a_socket,FIONBIO,&tru);
	return a_socket;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
HWND PutSocketToWSAAsyncSelect(SOCKET a_socket,LRESULT (CALLBACK *SocketMessageWndProc)(HWND wnd,UINT message,WPARAM wp,LPARAM lp),unsigned int wMsg)
{
	WNDCLASS wc;
	char ClassName[100];
	for(int i=0;i<300;i++)
	{
		memset(&wc,0,sizeof(WNDCLASS));
		// Register the main window class. 
		wc.style=0;
		wc.lpfnWndProc=(WNDPROC)SocketMessageWndProc;
		wc.cbClsExtra=0;
		wc.cbWndExtra=0; 
		wc.hInstance= (HINSTANCE)&__ImageBase;
		wc.hIcon=0;
		wc.hCursor=LoadCursor(NULL, IDC_ARROW);
		wc.hbrBackground=(HBRUSH)(COLOR_BTNFACE + 1);
		//wc.lpszMenuName= "MainMenu"; 
		#define ASYNC_SOCKET_CONTROL_WINDOW "AsyncSocketControlWindow:%d"
		_snprintf(ClassName,sizeof(ClassName),ASYNC_SOCKET_CONTROL_WINDOW,i);
		wc.lpszClassName=ClassName;

		if(RegisterClass(&wc) == 0)
		{
			UnregisterClass(ClassName,(HINSTANCE)&__ImageBase);
			if(RegisterClass(&wc) == 0)
			{
				printf("Registering Asynchrounous socket window failed\n");
				continue;
			}
		}
	}

	HWND message_window=CreateWindowEx(          
		0,//DWORD dwExStyle,
		wc.lpszClassName,//LPCTSTR lpClassName,
		NULL,//LPCTSTR lpWindowName,
		WS_POPUP,//DWORD dwStyle,
		0,//int x,
		0,//int y,
		100,//int nWidth,
		100,//int nHeight,
		NULL,//HWND hWndParent,
		NULL,//HMENU hMenu,
		wc.hInstance,//HINSTANCE hInstance,
		0//LPVOID lpParam
	);


	if (WSAAsyncSelect(
		a_socket,
		message_window,
		wMsg,
		FD_READ|FD_CLOSE) == SOCKET_ERROR) 
	{
		printf("failed to async select on server socket %d, %lu\n",
			a_socket,
			WSAGetLastError()
		);
		return message_window;
	}

	return message_window;
}
