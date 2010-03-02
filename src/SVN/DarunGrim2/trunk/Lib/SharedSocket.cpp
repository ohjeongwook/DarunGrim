#include <windows.h>
#include <stdio.h>
#include "SharedSocket.h"

#define MAXIMUM_TLV_SIZE 1024

BOOL SendTLVData(SOCKET client_socket,char type,PBYTE data,DWORD data_length)
{
	int result;
	PTLV p_tlv;
	int length=sizeof(TLV)+data_length;
	p_tlv=(PTLV)malloc(length);
	p_tlv->Type=type;
	p_tlv->Length=data_length;
	memcpy(p_tlv->Data,data,data_length);
	do
	{
		result=send(client_socket,(const char *)p_tlv,length,0);
		if(result==SOCKET_ERROR)
		{
			printf("send error: %d\n", WSAGetLastError());
			return FALSE;
		}
	}while(result==WSAEWOULDBLOCK);
	return TRUE;
}

int recv_data(SOCKET sock,char *buffer,int len,int flags)
{
	int current_pos=0;
	while(1)
	{
		int ret=recv(sock,buffer+current_pos,len-current_pos,flags);
		if(ret<0)
			return -1;
		current_pos+=ret;
		if(current_pos==len)
			return current_pos;
	}
}

PBYTE RecvTLVData(SOCKET client_socket,char *p_type,DWORD *p_length)
{
	//Must be in blocking mode
	TLV d_tlv;
	int result=0;
	result=recv_data(client_socket,(char *)&d_tlv,sizeof(d_tlv),0);
	if(result==sizeof(d_tlv))
	{
		if(d_tlv.Length<MAXIMUM_TLV_SIZE)
		{
			char *data_buffer=(char *)malloc(d_tlv.Length);
			if(data_buffer)
			{
				result=recv_data(client_socket,data_buffer,d_tlv.Length,0);
				if(result==d_tlv.Length)
				{
					if(p_type)
						*p_type=d_tlv.Type;
					if(p_length)
						*p_length=d_tlv.Length;
					return (PBYTE)data_buffer;
				}
			}
		}
	}
	else if (result==0)
	{
		//printf("Connection closing...\n");
		//return FALSE;
	}else
	{
		//msg("Got %d bytes only\n",result);
	}
	if(WSAGetLastError()!=WSAEWOULDBLOCK)
	{
		printf("recv failed: %d(result=%d)\n", WSAGetLastError(),result);
	}
	return NULL;
}

//extern int (*print_function)(const char *psz, ...)=printf;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
int (*gSharedSocketDataReceiver)(SOCKET data_socket,char type,DWORD length,PBYTE data);

void SetSharedSocketDataReceiver(int (*SharedSocketDataReceiver)(SOCKET data_socket,char type,DWORD length,PBYTE data))
{
	gSharedSocketDataReceiver=SharedSocketDataReceiver;
}

LRESULT CALLBACK SharedSocketDataReceiverWndProc(HWND wnd,UINT message,WPARAM wp,LPARAM lp)
{
	switch (message)
	{
		case WM_SHARED_SOCKET_EVENT:
			{
				switch (WSAGETSELECTEVENT(lp))
				{
					case FD_READ:
						{
							SOCKET data_socket=(SOCKET)wp;
							char type;
							DWORD length;
						
							PBYTE data=RecvTLVData(data_socket,&type,&length);
							if(data)
							{
								gSharedSocketDataReceiver(data_socket,type,length,data);
							}else{
								//msg("Got Error on Socket\n");
							}
						
							//WSAAsyncSelect: READ|CLOSE
							if (WSAAsyncSelect(data_socket ,
								wnd,
								WM_SHARED_SOCKET_EVENT,
								FD_READ|FD_CLOSE
							) == SOCKET_ERROR)
							{
								/*
								print_function("failed to async select client %d, %x data_socket=%d, message_window=%x\n", 
									data_socket,
									WSAGetLastError(),
									data_socket,
									message_window);
								*/
							}							
						}
						break;
					case FD_CLOSE:
						closesocket((SOCKET)wp);
						break;
				}
			}
			break;
		default:
			return DefWindowProc(wnd, message, wp, lp);
	}
	return 0;
}