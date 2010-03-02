#pragma warning(disable:4005)
#pragma warning(disable:4995)
//#include "Implementation.h"
#include "DiffMachine.h"
#include "IDAClientManager.h"
#include "OneIDAClientManager.h"
#include <cfixcc.h>
#include "DatabaseWriter.h"
#include <hash_set>
#include <hash_map>

class ExampleTest : public cfixcc::TestFixture
{
private:
	char *Filename;
public:
	ExampleTest()
	{
		//Filename="T:\\mat\\Projects\\ResearchTools\\Binary\\StaticAnalysis\\DarunGrim2\\src\\Bin\\Winhttp.db";
		Filename="T:\\mat\\Projects\\Binaries\\Microsoft Office\\Microsoft Corporation\\MSO\\Diff.dgf";
	}
	int ReadOffsetLength(
		char *filename,
		DWORD *pTheSourceLength,
		DWORD *pTheTargetLength,
		DWORD *pResultLength
	)
	{
		HANDLE hInFile=CreateFile(filename,// file to create
			GENERIC_READ,// open for writing
			0,// do not share
			NULL,// default security
			OPEN_EXISTING,// overwrite existing
			FILE_ATTRIBUTE_NORMAL|// normal file
			NULL,// asynchronous I/O
			NULL); // no attr. template
		if(hInFile==INVALID_HANDLE_VALUE) 
		{ 
			dprintf("Could not open file %s (error %d)\n",filename,GetLastError());
			return -1;
		}
		DWORD dwBytesRead;
		BOOL status;

		status=ReadFile(hInFile,
			pTheSourceLength,
			sizeof(DWORD),
			&dwBytesRead,
			NULL); 
		status=ReadFile(hInFile,
			pTheTargetLength,
			sizeof(DWORD),
			&dwBytesRead,
			NULL); 
		status=ReadFile(hInFile,
			pResultLength,
			sizeof(DWORD),
			&dwBytesRead,
			NULL); 
		CloseHandle(hInFile);
		return 0;
	}

  void TestReadingDGF() 
	{
		DWORD TheSourceLength=0;
		DWORD TheTargetLength=0;
		DWORD ResultLength=0;
		//char *Filename="T:\\mat\\Files\\IDB\\MS08-067-Vulnerability in Server Service Could Allow Remote Code Execution (958644)\\DiffRes.dgf";
		//char *Filename="T:\\mat\\Files\\MS Patches\\Microsoft Security Bulletin MS09-002 - Critical Cumulative Security Update for Internet Explorer (961260)\\ms09-002.dgf";
		char *Filename="ms09-002.dgf";
		ReadOffsetLength(
			Filename,
			&TheSourceLength,
			&TheTargetLength,
			&ResultLength
		);

		OneIDAClientManager *pOneClientManagerTheSource=new OneIDAClientManager();
		DWORD CurrentOffset=sizeof(DWORD)*3;
		pOneClientManagerTheSource->Retrieve(Filename,CurrentOffset,TheSourceLength);

		CurrentOffset+=TheSourceLength;
		OneIDAClientManager *pOneClientManagerTheTarget=new OneIDAClientManager();
		pOneClientManagerTheTarget->Retrieve(Filename,CurrentOffset,TheTargetLength);
		CurrentOffset+=TheTargetLength;

		DiffMachine *pDiffMachine=new DiffMachine(pOneClientManagerTheSource,pOneClientManagerTheTarget);
		pDiffMachine->Retrieve(Filename,CurrentOffset,ResultLength);
		CurrentOffset+=ResultLength;

		int MatchCount=pDiffMachine->GetFunctionMatchInfoCount();
		for(int i=0;i<MatchCount;i++)
		{
			FunctionMatchInfo match_info=pDiffMachine->GetFunctionMatchInfo(i);
			if(match_info.BlockType==FUNCTION_BLOCK)
			{
				/*
				int index=AddItemToDiffListView(
					match_info.TheSourceFunctionName,
					match_info.NoneMatchCountForTheSource,
					match_info.TheTargetFunctionName,
					match_info.NoneMatchCountForTheTarget,
					match_info.MatchCountWithModificationForTheSource,
					match_info.MatchCountForTheSource,
					i);*/
			}
		}
	}

  
	void TestReadingIDARawDataFile() 
	{
		const char *Filename="T:\\mat\\Projects\\ResearchTools\\Binary\\StaticAnalysis\\DarunGrim2\\src\\Automation\\disassembly.info";
		OneIDAClientManager *pOneClientManagerTheTarget=new OneIDAClientManager();
		pOneClientManagerTheTarget->RetrieveIDARawDataFromFile(Filename);
	}

	void TestReadingDiffMachineDB()
	{
		DBWrapper InputDB(Filename);
		CreateTables(InputDB);
		DiffMachine *pDiffMachine=new DiffMachine();
		pDiffMachine->Retrieve(InputDB);
		InputDB.CloseDatabase();
	}

	void TestOneIDAClientManagerDB()
	{
		DBWrapper InputDB(Filename);
		CreateTables(InputDB);
		OneIDAClientManager *pOneClientManagerTheTarget=new OneIDAClientManager();
		//pOneClientManagerTheTarget->Retrieve(InputDB);
		InputDB.CloseDatabase();
	}

	static int ReadFunctionMembersResultsCallback(void *arg,int argc,char **argv,char **names)
	{
		multimap <DWORD,DWORD> *FunctionMembers=(multimap <DWORD,DWORD> *)arg;
		if(FunctionMembers)
		{
			FunctionMembers->insert(pair <DWORD,DWORD>(atol(argv[0]),atol(argv[1])));
		}
		return 0;
	}

	multimap <DWORD,DWORD> *LoadFunctionMembersMap(DBWrapper &InputDB,DWORD FileID)
	{
		multimap <DWORD,DWORD> *FunctionMembers=new multimap <DWORD,DWORD>;
		int Count=0;
		InputDB.ExecuteStatement(ReadFunctionMembersResultsCallback,FunctionMembers,"SELECT FunctionAddress,StartAddress FROM OneLocationInfo WHERE FileID=%d AND FunctionAddress!=0",FileID);
		dprintf("Count=%d\n",FunctionMembers->size());
		/*
		multimap <DWORD,DWORD>::iterator FunctionMembersIter;
		DWORD FunctionAddress=0;
		for(FunctionMembersIter=FunctionMembers->begin();FunctionMembersIter!=FunctionMembers->end();FunctionMembersIter++)
		{
			if(FunctionAddress!=FunctionMembersIter->first)
			{
				FunctionAddress=FunctionMembersIter->first;
				dprintf("%x\n",FunctionAddress);
			}
			dprintf("\t%x\n",FunctionMembersIter->second);
		}*/
		return FunctionMembers;
	}

	static int ReadAddressToFunctionMapResultsCallback(void *arg,int argc,char **argv,char **names)
	{
		hash_map <DWORD,DWORD> *AddressToFunctionMap=(hash_map <DWORD,DWORD> *)arg;
		if(AddressToFunctionMap)
		{
			AddressToFunctionMap->insert(pair <DWORD,DWORD>(atol(argv[0]),atol(argv[1])));
		}
		return 0;
	}

	hash_map <DWORD,DWORD> *LoadAddressToFunctionMap(DBWrapper &InputDB,DWORD FileID)
	{
		hash_map <DWORD,DWORD> *AddressToFunctionMap=new hash_map <DWORD,DWORD>;
		int Count=0;
		InputDB.ExecuteStatement(ReadAddressToFunctionMapResultsCallback,AddressToFunctionMap,"SELECT StartAddress,FunctionAddress FROM OneLocationInfo WHERE FileID=%d AND FunctionAddress!=0",FileID);
		dprintf("Count=%d\n",AddressToFunctionMap->size());
		hash_map <DWORD,DWORD>::iterator AddressToFunctionMapIter;
		/*
		DWORD FunctionAddress=0;
		for(AddressToFunctionMapIter=AddressToFunctionMap->begin();AddressToFunctionMapIter!=AddressToFunctionMap->end();AddressToFunctionMapIter++)
		{
			if(FunctionAddress!=AddressToFunctionMapIter->first)
			{
				FunctionAddress=AddressToFunctionMapIter->first;
				dprintf("%x\n",FunctionAddress);
			}
			dprintf("\t%x\n",AddressToFunctionMapIter->second);
		}*/
		return AddressToFunctionMap;
	}
	
	void TestReadFunctionMembers()
	{
		DBWrapper InputDB(Filename);
		CreateTables(InputDB);
		//OneIDAClientManager *pOneClientManagerTheTarget=new OneIDAClientManager();
		//pOneClientManagerTheTarget->Retrieve(InputDB);
		multimap <DWORD,DWORD> *FunctionMembersMapForTheSource=LoadFunctionMembersMap(InputDB,1);
		hash_map <DWORD,DWORD> *AddressToFunctionMapForTheTarget=LoadAddressToFunctionMap(InputDB,2);
		FunctionMembersMapForTheSource->clear();
		delete FunctionMembersMapForTheSource;
		AddressToFunctionMapForTheTarget->clear();
		delete AddressToFunctionMapForTheTarget;
		InputDB.CloseDatabase();
	}
};

CFIXCC_BEGIN_CLASS( ExampleTest )
	//CFIXCC_METHOD( TestReadingDGF )
	//CFIXCC_METHOD( TestReadingIDARawDataFile )
	//CFIXCC_METHOD( TestReadingDB )
	//CFIXCC_METHOD( TestReadingDiffMachineDB )
	//CFIXCC_METHOD( TestOneIDAClientManagerDB )
	CFIXCC_METHOD( TestReadFunctionMembers )	
CFIXCC_END_CLASS()
