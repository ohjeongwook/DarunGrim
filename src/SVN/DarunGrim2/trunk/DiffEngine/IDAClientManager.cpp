#include <winsock2.h>

#include "IDAClientManager.h"
#include "SocketOperation.h"
#include "dprintf.h"

#define DATA_BUFSIZE 4096

IDAClientManager::IDAClientManager(unsigned short port,DBWrapper *OutputDB)
{
	m_OutputDB=OutputDB;
	ListeningPort=port;
	ListeningSocket=CreateListener(NULL,port);
	dprintf("%s: ListeningSocket=%d\n",__FUNCTION__,ListeningSocket);
}

IDAClientManager::~IDAClientManager()
{
}

OneIDAClientManager *IDAClientManager::GetOneIDAClientManagerFromFile(char *DataFile)
{
	OneIDAClientManager *pOneIDAClientManager=new OneIDAClientManager(m_OutputDB);
	pOneIDAClientManager->Retrieve(DataFile);
	return pOneIDAClientManager;
}

BOOL IDAClientManager::AssociateSocket(OneIDAClientManager *pOneIDAClientManager,bool RetrieveData)
{
	SOCKET ClientSocket=accept(ListeningSocket,NULL,NULL);
	dprintf("%s: accepting=%d\n",__FUNCTION__,ClientSocket);
	if(ClientSocket==INVALID_SOCKET)
	{
		int error=WSAGetLastError();
		dprintf("Socket error=%d\n",error);
		return FALSE;
	}else
	{
		if(RetrieveData)
		{
			dprintf("%s: Calling RetrieveIDARawDataFromSocket\n",__FUNCTION__);
			pOneIDAClientManager->RetrieveIDARawDataFromSocket(ClientSocket);
		}
		else
		{
			dprintf("%s: SetSocket\n",__FUNCTION__);
			pOneIDAClientManager->SetSocket(ClientSocket);
		}
		return TRUE;
	}
	return FALSE;
}

DWORD IDAClientManager::SetMembers(OneIDAClientManager *OneIDAClientManagerTheSource,OneIDAClientManager *OneIDAClientManagerTheTarget,DiffMachine *pArgDiffMachine)
{
	TheSource=OneIDAClientManagerTheSource;
	TheTarget=OneIDAClientManagerTheTarget;
	pDiffMachine=pArgDiffMachine;
	return 1;
}

DWORD IDAClientManager::IDACommandProcessor()
{
	SOCKET SocketArray[WSA_MAXIMUM_WAIT_EVENTS];
	WSAEVENT EventArray[WSA_MAXIMUM_WAIT_EVENTS];
	WSANETWORKEVENTS NetworkEvents;
	DWORD EventTotal=0,index;

	SocketArray[0]=TheSource->GetSocket();
	SocketArray[1]=TheTarget->GetSocket();
	for(int i=0;i<2;i++)
	{
		WSAEVENT NewEvent=WSACreateEvent();
		WSAEventSelect(SocketArray[i],NewEvent,FD_READ|FD_CLOSE);
		EventArray[EventTotal]=NewEvent;
		EventTotal++;
	}
	while(1)
	{
		index=WSAWaitForMultipleEvents(EventTotal,
			EventArray,
			FALSE,
			WSA_INFINITE,
			FALSE);
		if(index<0)
			break;
			
		index=index-WSA_WAIT_EVENT_0;
		//-------------------------
		// Iterate through all events and enumerate
		// if the wait does not fail.
		for(DWORD i=index; i<EventTotal; i++)
		{
			if(SocketArray[i]==WSA_INVALID_HANDLE)
				continue;
			index=WSAWaitForMultipleEvents(1,
				&EventArray[i],
				TRUE,
				1000,
				FALSE);
			if ((index !=WSA_WAIT_FAILED) && (index !=WSA_WAIT_TIMEOUT))
			{
				if(WSAEnumNetworkEvents(SocketArray[i],EventArray[i],&NetworkEvents)==0)
				{
					dprintf("Signal(%d - %d)\n",i,NetworkEvents.lNetworkEvents);
					if(NetworkEvents.lNetworkEvents==FD_READ)
					{
						char buffer[DATA_BUFSIZE]={0,};
						WSABUF DataBuf;
						DataBuf.len=DATA_BUFSIZE;
						DataBuf.buf=buffer;
						/*
						DWORD RecvBytes;
						DWORD Flags=0;
						if (WSARecv(SocketArray[i],&DataBuf,1,&RecvBytes,&Flags,NULL,NULL)==SOCKET_ERROR)
						{
							dprintf("Error occurred at WSARecv()\n");
						}else
						{
							dprintf("Read %d bytes\n",RecvBytes);
						}*/
						char type;
						DWORD length;
						PBYTE data=RecvTLVData(SocketArray[i],&type,&length);
						if(data)
						{
							dprintf("%s: Type: %d Length: %d data:%x\n",__FUNCTION__,type,length,data);
							if(type==SHOW_MATCH_ADDR && length>=4)
							{
								DWORD address=*(DWORD *)data;
								dprintf("%s: Showing address=%x\n",__FUNCTION__,address);
								//Get Matching Address
								DWORD MatchingAddress=pDiffMachine->GetMatchAddr(i,address);
								if(MatchingAddress!=0)
								{
									//Show using JUMP_TO_ADDR
									if(i==0)
									{
										TheTarget->ShowAddress(MatchingAddress);
									}else
									{
										TheSource->ShowAddress(MatchingAddress);
									}
								}
							}
						}						
					}else if(NetworkEvents.lNetworkEvents==FD_CLOSE)
					{
						closesocket(SocketArray[i]);
						WSACloseEvent(EventArray[i]);
						memcpy(SocketArray+i,SocketArray+i+1,EventTotal-i+1);
						memcpy(EventArray+i,EventArray+i+1,EventTotal-i+1);
						EventTotal--;
					}
				}
			}
		}
	}
	return 1;
}

DWORD WINAPI CreateIDACommandProcessorCallback(LPVOID lpParameter)
{
	IDAClientManager *pIDAClientManager=(IDAClientManager *)lpParameter;
	pIDAClientManager->IDACommandProcessor();
	return 1;
}

DWORD IDAClientManager::CreateIDACommandProcessor()
{
	DWORD dwThreadId;
	CreateThread(NULL,0,CreateIDACommandProcessorCallback,(PVOID)this,0,&dwThreadId);
	return 1;
}

void IDAClientManager::ShowResultsOnIDA()
{
	vector <FunctionMatchInfo>::iterator iter;
	for(iter=pDiffMachine->FunctionMatchInfoList.begin();iter!=pDiffMachine->FunctionMatchInfoList.end();iter++)
	{
		TheSource->SendTLVData(
			ADD_MATCH_ADDR,
			(PBYTE)&(*iter),
			sizeof(*iter));
	}
	/*TODO:
	for(iter=ReverseFunctionMatchInfoList.begin();iter!=ReverseFunctionMatchInfoList.end();iter++)
	{
		TheTarget->SendTLVData(
			ADD_MATCH_ADDR,
			(PBYTE)&(*iter),
			sizeof(*iter));
	}*/

	hash_set <DWORD>::iterator unidentified_iter;
	for(unidentified_iter=pDiffMachine->TheSourceUnidentifedBlockHash.begin();unidentified_iter!=pDiffMachine->TheSourceUnidentifedBlockHash.end();unidentified_iter++)
	{
		TheSource->SendTLVData(
			ADD_UNINDENTIFIED_ADDR,
			(PBYTE)&(*unidentified_iter),
			sizeof(DWORD));
	}
	for(unidentified_iter=pDiffMachine->TheTargetUnidentifedBlockHash.begin();unidentified_iter!=pDiffMachine->TheTargetUnidentifedBlockHash.end();unidentified_iter++)
	{
		TheTarget->SendTLVData(
			ADD_UNINDENTIFIED_ADDR,
			(PBYTE)&(*unidentified_iter),
			sizeof(DWORD));
	}
	TheSource->SendTLVData(
		SHOW_DATA,
		(PBYTE)"test",
		4);
	TheTarget->SendTLVData(
		SHOW_DATA,
		(PBYTE)"test",
		4);	
}