#pragma once
#include "DiffMachine.h"
#include "DataStructure.h"
#include "DBWrapper.h"

class IDAClientManager
{
private:
	DBWrapper *m_OutputDB;
	unsigned short ListeningPort;
	SOCKET ListeningSocket;
	OneIDAClientManager *OneIDAClientManagers[2];

	OneIDAClientManager *TheSource;
	OneIDAClientManager *TheTarget;
	DiffMachine *pDiffMachine;
public:
	IDAClientManager(unsigned short port,DBWrapper *OutputDB=NULL);
	~IDAClientManager();
	BOOL AssociateSocket(OneIDAClientManager *pOneIDAClientManager,bool RetrieveData=FALSE);
	OneIDAClientManager *GetOneIDAClientManagerFromFile(char *DataFile);
	DWORD SetMembers(OneIDAClientManager *OneIDAClientManagerTheSource,OneIDAClientManager *OneIDAClientManagerTheTarget,DiffMachine *pArgDiffMachine);
	DWORD IDACommandProcessor();
	DWORD CreateIDACommandProcessor();
	void ShowResultsOnIDA();
};
