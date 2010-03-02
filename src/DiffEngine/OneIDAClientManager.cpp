#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "OneIDAClientManager.h"
#include <string>
#include "dprintf.h"

#define strtoul10(X) strtoul(X,NULL,10)

//DB Related
#include "sqlite3.h"
#include "DBWrapper.h"
#include "DataBaseWriter.h"

#include <hash_set>
using namespace std;
using namespace stdext;

#define DEBUG_LEVEL 0
extern int DebugLevel;

char *MapInfoTypesStr[]={"Call","Cref From","Cref To","Dref From","Dref To"};
int types[]={CREF_FROM,CREF_TO,CALL,DREF_FROM,DREF_TO,CALLED};

OneIDAClientManager::OneIDAClientManager(DBWrapper *OutputDB)
{
	ClientAnalysisInfo=NULL;
	m_FileID=0;
	m_OutputDB=OutputDB;
	DisasmLine=NULL;
	Socket=INVALID_SOCKET;
	m_OriginalFilePath=NULL;
}

OneIDAClientManager::~OneIDAClientManager()
{
	if(m_OriginalFilePath)
		free(m_OriginalFilePath);
}

PBYTE OneIDAClientManager::ZlibWrapperRetrieveCallback(PVOID Context,BYTE *pType,DWORD *pLength)
{
	*pLength=0;
	*pType=END_OF_DATA;
	PBYTE Data=NULL;

	ZlibWrapper *pZlibWrapper=(ZlibWrapper *)Context;
	if(pZlibWrapper->ReadData(pType,sizeof(*pType))<=0)
	{
		*pType=END_OF_DATA;
		return NULL;
	}
	if(pZlibWrapper->ReadData((unsigned char *)pLength,sizeof(*pLength))<=0)
	{
		*pType=END_OF_DATA;
		return NULL;
	}

	if(*pLength>0)
	{
		Data=(PBYTE)malloc(*pLength);
		if(Data)
		{
			if(pZlibWrapper->ReadData((unsigned char *)Data,*pLength)<=0)
			{
				free(Data);
				Data=NULL;
				*pType=END_OF_DATA;
			}
		}else
		{
			*pType=END_OF_DATA;
		}
	}
	return  Data;
}

BOOL OneIDAClientManager::RetrieveIDARawDataFromFile(const char *Filename)
{
	ZlibWrapper *zlib_wrapper=new ZlibWrapper(FALSE);
	zlib_wrapper->SetInFile((char *)Filename,0,FILE_BEGIN);
	RetrieveIDARawData((PBYTE (*)(PVOID Context,BYTE *Type,DWORD *Length))ZlibWrapperRetrieveCallback,(PVOID)zlib_wrapper);
	return TRUE;
}

void OneIDAClientManager::SetSocket(SOCKET socket)
{
	Socket=socket;
}

BOOL OneIDAClientManager::RetrieveIDARawDataFromSocket(SOCKET socket)
{
	Socket=socket;
	ClientAnalysisInfo=NULL;
	char shared_memory_name[1024];
	_snprintf(shared_memory_name,sizeof(shared_memory_name),"DG Shared Memory - %u - %u",
		GetCurrentProcessId(),
		GetCurrentThreadId());

	if(DebugLevel&1) dprintf("%s: ID=%d InitDataSharer\n",__FUNCTION__);
	#define SHARED_MEMORY_SIZE 100000
	if(!InitDataSharer(&IDADataSharer,
		shared_memory_name,
		SHARED_MEMORY_SIZE,
		TRUE))
	{
		if(DebugLevel&1) dprintf("%s: ID=%d InitDataSharer failed\n",__FUNCTION__);
		return FALSE;
	}
	char data[1024+sizeof(DWORD)];
	*(DWORD *)data=SHARED_MEMORY_SIZE;
	memcpy(data+sizeof(DWORD),shared_memory_name,strlen(shared_memory_name)+1);
	if(DebugLevel&1) dprintf("%s: ID=%d SendTLVData SEND_ANALYSIS_DATA\n",__FUNCTION__);
	if(SendTLVData(SEND_ANALYSIS_DATA,(PBYTE)data,sizeof(DWORD)+strlen(shared_memory_name)+1))
	{
		if(DebugLevel&1) dprintf("%s: ID=%d RetrieveIDARawData\n",__FUNCTION__);
		RetrieveIDARawData((PBYTE (*)(PVOID Context,BYTE *Type,DWORD *Length))GetData,(PVOID)&IDADataSharer);
		return TRUE;
	}
	return FALSE;
}

DWORD *OneIDAClientManager::GetMappedAddresses(DWORD address,int type,int *p_length)
{
	DWORD *addresses=NULL;
	int current_size=50;

	addresses=(DWORD *)malloc(sizeof(DWORD)*current_size);
	int addresses_i=0;

	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;
	for(map_info_hash_map_pIter=ClientAnalysisInfo->map_info_hash_map.find(address);
		map_info_hash_map_pIter!=ClientAnalysisInfo->map_info_hash_map.end();
		map_info_hash_map_pIter++
		)
	{
		if(map_info_hash_map_pIter->first!=address)
			break;
		if(map_info_hash_map_pIter->second->Type==type)
		{
			//map_info_hash_map_pIter->second->Dst
			//TODO: add
			if(current_size<addresses_i+2)
			{
				current_size+=50;
				addresses=(DWORD *)realloc(addresses,sizeof(DWORD)*(current_size));
			}
			addresses[addresses_i]=map_info_hash_map_pIter->second->Dst;
			addresses_i++;
			addresses[addresses_i]=NULL;
		}
	}

	if(p_length)
		*p_length=addresses_i;
	if(addresses_i==0)
	{
		free(addresses);
		addresses=NULL;
	}
	return addresses;
}

#undef USE_LEGACY_MAP_FOR_ADDRESS_HASH_MAP
void OneIDAClientManager::RemoveFromFingerprintHash(DWORD address)
{
	unsigned char *Fingerprint=NULL;
#ifdef USE_LEGACY_MAP_FOR_ADDRESS_HASH_MAP
	multimap <DWORD ,unsigned char *,hash_compare_fingerprint >::iterator address_fingerprint_hash_map_PIter=ClientAnalysisInfo->address_fingerprint_hash_map.find(address);
	if(address_fingerprint_hash_map_PIter!=ClientAnalysisInfo->address_fingerprint_hash_map.end())
	{
		Fingerprint=(char *)address_fingerprint_hash_map_PIter->second;
#else
		char *FingerprintStr=NULL;
		m_OutputDB->ExecuteStatement(m_OutputDB->ReadRecordStringCallback,&FingerprintStr,"SELECT Fingerprint FROM OneLocationInfo WHERE FileID=%u and StartAddress=%u",m_FileID,address);
		if(FingerprintStr)
		{
			Fingerprint=HexToBytesWithLengthAmble(FingerprintStr);
		}
#endif
		if(Fingerprint)
		{
			multimap <unsigned char *,DWORD,hash_compare_fingerprint>::iterator fingerprint_hash_map_PIter;
			for(fingerprint_hash_map_PIter=ClientAnalysisInfo->fingerprint_hash_map.find(Fingerprint);
				fingerprint_hash_map_PIter!=ClientAnalysisInfo->fingerprint_hash_map.end();
				fingerprint_hash_map_PIter++
			)
			{
				if(!IsEqualByteWithLengthAmble(fingerprint_hash_map_PIter->first,Fingerprint))
					break;
				if(fingerprint_hash_map_PIter->second==address)
				{
					ClientAnalysisInfo->fingerprint_hash_map.erase(fingerprint_hash_map_PIter);
					break;
				}
			}
#ifndef USE_LEGACY_MAP_FOR_ADDRESS_HASH_MAP
			free(Fingerprint);
#endif
		}
#ifdef USE_LEGACY_MAP_FOR_ADDRESS_HASH_MAP
	}
#endif
}

char *OneIDAClientManager::GetFingerPrintStr(DWORD address)
{
	if(ClientAnalysisInfo->address_fingerprint_hash_map.size()>0)
	{
		multimap <DWORD ,unsigned char *>::iterator address_fingerprint_hash_map_PIter=ClientAnalysisInfo->address_fingerprint_hash_map.find(address);
		if(address_fingerprint_hash_map_PIter!=ClientAnalysisInfo->address_fingerprint_hash_map.end())
		{
			return BytesWithLengthAmbleToHex(address_fingerprint_hash_map_PIter->second);
		}
	}else
	{
		char *FingerprintPtr=NULL;
		m_OutputDB->ExecuteStatement(m_OutputDB->ReadRecordStringCallback,&FingerprintPtr,"SELECT Fingerprint FROM OneLocationInfo WHERE FileID=%u and StartAddress=%u",m_FileID,address);
		return FingerprintPtr;
	}
	return NULL;
}

char *OneIDAClientManager::GetName(DWORD address)
{
#ifdef USE_LEGACY_MAP
	multimap <DWORD, string>::iterator address_name_hash_map_iter;

	address_name_hash_map_iter=ClientAnalysisInfo->address_name_hash_map.find(address);
	if(address_name_hash_map_iter!=ClientAnalysisInfo->address_name_hash_map.end())
	{
		return _strdup((*address_name_hash_map_iter).second.c_str());
	}
	return NULL;
#else
	char *Name=NULL;
	m_OutputDB->ExecuteStatement(m_OutputDB->ReadRecordStringCallback,&Name,"SELECT Name FROM OneLocationInfo WHERE FileID=%u and StartAddress=%u",m_FileID,address);
	return Name;
#endif
}

DWORD OneIDAClientManager::GetBlockAddress(DWORD address)
{
#ifdef USE_LEGACY_MAP
	while(1)
	{
		if(ClientAnalysisInfo->address_hash_map.find(address)!=ClientAnalysisInfo->address_hash_map.end())
			break;
		address--;
	}
	return address;
#else
	DWORD BlockAddress=address;
	m_OutputDB->ExecuteStatement(m_OutputDB->ReadRecordIntegerCallback,&BlockAddress,"SELECT StartAddress FROM OneLocationInfo WHERE FileID=%u and StartAddress <= %u  and %u <= EndAddress LIMIT 1",m_FileID,address,address);
	return BlockAddress;
#endif
}

void OneIDAClientManager::DumpBlockInfo(DWORD block_address)
{
	int addresses_number;
	char *type_descriptions[]={"Cref From","Cref To","Call","Dref From","Dref To"};
	for(int i=0;i<sizeof(types)/sizeof(int);i++)
	{
		DWORD *addresses=GetMappedAddresses(
			block_address,
			types[i],
			&addresses_number);
		if(addresses)
		{
			if(DebugLevel&1) dprintf("%s: ID=%d %s: ",__FUNCTION__,m_FileID,type_descriptions[i]);
			for(int j=0;j<addresses_number;j++)
			{
				if(DebugLevel&1) dprintf("%s: ID=%d %x ",__FUNCTION__,m_FileID,addresses[j]);
			}
			if(DebugLevel&1) dprintf("\n");
		}
	}
	char *hex_str=GetFingerPrintStr(block_address);
	if(hex_str)
	{
		if(DebugLevel&1) dprintf("%s: ID=%d fingerprint: %s\n",__FUNCTION__,m_FileID,hex_str);
		free(hex_str);
	}
}

const char *GetAnalysisDataTypeStr(int type)
{
	static const char *Types[]={"ONE_LOCATION_INFO","MAP_INFO","FILE_INFO","END_OF_DATA"};
	if(type<sizeof(Types)/sizeof(Types[0]))
		return Types[type];
	return "Unknown";
}

enum {TYPE_FILE_INFO,TYPE_ADDRESS_HASH_MAP,TYPE_ADDRESS_DISASSEMBLY_MAP,TYPE_FINGERPRINT_HASH_MAP,TYPE_TWO_LEVEL_FINGERPRINT_HASH_MAP,TYPE_ADDRESS_FINGERPRINT_HASH_MAP,TYPE_NAME_HASH_MAP,TYPE_ADDRESS_NAME_HASH_MAP,TYPE_MAP_INFO_HASH_MAP};

const char *GetFileDataTypeStr(int type)
{
	static const char *Types[]={"FILE_INFO","ADDRESS_HASH_MAP","ADDRESS_DISASSEMBLY_MAP","FINGERPRINT_HASH_MAP","TWO_LEVEL_FINGERPRINT_HASH_MAP","ADDRESS_FINGERPRINT_HASH_MAP","NAME_HASH_MAP","ADDRESS_NAME_HASH_MAP","MAP_INFO_HASH_MAP"};
	if(type<sizeof(Types)/sizeof(Types[0]))
		return Types[type];
	return "Unknown";
}

BOOL OneIDAClientManager::Save(char *DataFile,DWORD Offset,DWORD dwMoveMethod,hash_set <DWORD> *pSelectedAddresses)
{
#ifdef USE_LEGACY_MAP
	ZlibWrapper *zlib_wrapper=new ZlibWrapper(TRUE,1);
	zlib_wrapper->SetOutFile(DataFile,Offset,dwMoveMethod);

	BOOL ret;
	/*
	enum {FILE_INFO,ADDRESS_HASH_MAP,ADDRESS_DISASSEMBLY_MAP,FINGERPRINT_HASH_MAP,TWO_LEVEL_FINGERPRINT_HASH_MAP,ADDRESS_FINGERPRINT_HASH_MAP,NAME_HASH_MAP,ADDRESS_NAME_HASH_MAP,MAP_INFO_HASH_MAP};
	*/
	//FileInfo file_info;
	char type=TYPE_FILE_INFO;
	ret=zlib_wrapper->WriteData((unsigned char *)
		&type,
		sizeof(type));
	if(!ret)
		return FALSE;
	ret=zlib_wrapper->WriteData((unsigned char *)
		&ClientAnalysisInfo->file_info,
		sizeof(ClientAnalysisInfo->file_info));
	if(!ret)
		return FALSE;
	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_iter;
	for(address_hash_map_iter=ClientAnalysisInfo->address_hash_map.begin();
		address_hash_map_iter!=ClientAnalysisInfo->address_hash_map.end();
		address_hash_map_iter++)
	{
		if(
			pSelectedAddresses &&
			pSelectedAddresses->find(address_hash_map_iter->first)==
			pSelectedAddresses->end()
		)
		{
			continue;
		}

		char type=TYPE_ADDRESS_HASH_MAP;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&type,
			sizeof(type));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&address_hash_map_iter->first,
			sizeof(address_hash_map_iter->first));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			address_hash_map_iter->second,
			sizeof(*(address_hash_map_iter->second)));
		if(!ret)
			return FALSE;
	}
	//multimap <DWORD, string> address_disassembly_hash_map;
	multimap <DWORD, string>::iterator address_disassembly_hash_map_iter;
	for(address_disassembly_hash_map_iter=ClientAnalysisInfo->address_disassembly_hash_map.begin();
		address_disassembly_hash_map_iter!=ClientAnalysisInfo->address_disassembly_hash_map.end();
		address_disassembly_hash_map_iter++)
	{
		if(
			pSelectedAddresses &&
			pSelectedAddresses->find(address_disassembly_hash_map_iter->first)==
			pSelectedAddresses->end()
		)
		{
			continue;
		}
		char type=TYPE_ADDRESS_DISASSEMBLY_MAP;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&type,
			sizeof(type));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&address_disassembly_hash_map_iter->first,
			sizeof(address_disassembly_hash_map_iter->first));
		if(!ret)
			return FALSE;
		unsigned short length=strlen(address_disassembly_hash_map_iter->second.c_str());
		ret=zlib_wrapper->WriteData((unsigned char *)
			&length,
			sizeof(length));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			address_disassembly_hash_map_iter->second.c_str(),
			length);
		if(!ret)
			return FALSE;
	}
	//multimap <DWORD ,string> address_fingerprint_hash_map;
	multimap <DWORD, string>::iterator address_fingerprint_hash_map_iter;
	for(address_fingerprint_hash_map_iter=ClientAnalysisInfo->address_fingerprint_hash_map.begin();
		address_fingerprint_hash_map_iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end();
		address_fingerprint_hash_map_iter++)
	{
		if(
			pSelectedAddresses &&
			pSelectedAddresses->find(address_fingerprint_hash_map_iter->first)==
			pSelectedAddresses->end()
		)
		{
			continue;
		}
		char type=TYPE_ADDRESS_FINGERPRINT_HASH_MAP;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&type,
			sizeof(type));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&address_fingerprint_hash_map_iter->first,
			sizeof(address_fingerprint_hash_map_iter->first));
		if(!ret)
			return FALSE;
		unsigned short length=strlen(address_fingerprint_hash_map_iter->second.c_str());
		ret=zlib_wrapper->WriteData((unsigned char *)
			&length,
			sizeof(length));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			address_fingerprint_hash_map_iter->second.c_str(),
			length);
		if(!ret)
			return FALSE;
	}
	//multimap <DWORD,string> address_name_hash_map;
	multimap <DWORD, string>::iterator address_name_hash_map_iter;
	for(address_name_hash_map_iter=ClientAnalysisInfo->address_name_hash_map.begin();
		address_name_hash_map_iter!=ClientAnalysisInfo->address_name_hash_map.end();
		address_name_hash_map_iter++)
	{
		if(
			pSelectedAddresses &&
			pSelectedAddresses->find(address_name_hash_map_iter->first)==
			pSelectedAddresses->end()
		)
		{
			continue;
		}
		char type=TYPE_ADDRESS_NAME_HASH_MAP;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&type,
			sizeof(type));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&address_name_hash_map_iter->first,
			sizeof(address_name_hash_map_iter->first));
		if(!ret)
			return FALSE;
		unsigned short length=strlen(address_name_hash_map_iter->second.c_str());
		ret=zlib_wrapper->WriteData((unsigned char *)
			&length,
			sizeof(length));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			address_name_hash_map_iter->second.c_str(),
			length);
		if(!ret)
			return FALSE;
	}
	//multimap <DWORD, PMapInfo> map_info_hash_map;
	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_iter;
	for(map_info_hash_map_iter=ClientAnalysisInfo->map_info_hash_map.begin();
		map_info_hash_map_iter!=ClientAnalysisInfo->map_info_hash_map.end();
		map_info_hash_map_iter++)
	{
		if(
			pSelectedAddresses &&
			pSelectedAddresses->find(map_info_hash_map_iter->first)==
			pSelectedAddresses->end()
		)
		{
			continue;
		}
		char type=TYPE_MAP_INFO_HASH_MAP;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&type,
			sizeof(type));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			&map_info_hash_map_iter->first,
			sizeof(map_info_hash_map_iter->first));
		if(!ret)
			return FALSE;
		ret=zlib_wrapper->WriteData((unsigned char *)
			map_info_hash_map_iter->second,
			sizeof(*(map_info_hash_map_iter->second)));
		if(!ret)
			return FALSE;
	}

	delete zlib_wrapper;
#endif
	return TRUE;
}

char *OneIDAClientManager::RetrieveString(ZlibWrapper *zlib_wrapper)
{
	unsigned short length;
	DWORD nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
		&length,
		sizeof(length)); 
	if(nBytesRead!=sizeof(length))
		return NULL;

	if(length<0xff00)
	{
		char *buffer=(char *)malloc(length+1);
		if(buffer)
		{
			buffer[length]=0;
			nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
				buffer,
				length); 
			if(nBytesRead!=length)
			{
				delete buffer;
				return NULL;
			}
		}
		return buffer;
	}
	return NULL;
}

BOOL OneIDAClientManager::Retrieve(char *DataFile,DWORD Offset,DWORD Length)
{
#ifdef USE_LEGACY_MAP
	ZlibWrapper *zlib_wrapper=new ZlibWrapper(FALSE);
	if(!zlib_wrapper->SetInFile(DataFile,Offset,Length))
		return FALSE;
	int TypesCount[10]={0,};

	for(int i=0;i<10;i++)
		TypesCount[i]=0;

	ClientAnalysisInfo=new AnalysisInfo;
	while(1)
	{
		DWORD  nBytesRead;
		char type;

		nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
			&type, 
			sizeof(type)) ; 

		if(nBytesRead!=sizeof(type))
			break;
		if(type<sizeof(TypesCount)/sizeof(TypesCount[0]))
		TypesCount[type]++;
		switch(type)
		{
			case TYPE_FILE_INFO:
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					&ClientAnalysisInfo->file_info,
					sizeof(ClientAnalysisInfo->file_info)) ; 
				break;
			case TYPE_ADDRESS_HASH_MAP:
			{
				//multimap <DWORD, POneLocationInfo> address_hash_map;
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					&address,
					sizeof(address));
				POneLocationInfo pOneLocationInfo=new OneLocationInfo;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					pOneLocationInfo,
					sizeof(OneLocationInfo)); 
				ClientAnalysisInfo->address_hash_map.insert(AddrPOneLocationInfo_Pair(address,pOneLocationInfo));
				break;
			}
			case TYPE_ADDRESS_DISASSEMBLY_MAP:
			{
				//multimap <DWORD, string> address_disassembly_hash_map;
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					&address,
					sizeof(address)); 
				char *name=RetrieveString(zlib_wrapper);
				if(name)
				{
					//something wrong?
					ClientAnalysisInfo->address_disassembly_hash_map.insert(AddrDisassembly_Pair(address,name));
					free(name);
				}
				break;
			}
			case TYPE_ADDRESS_FINGERPRINT_HASH_MAP:
			{
				//multimap <DWORD ,string> address_fingerprint_hash_map;
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					&address,
					sizeof(address)); 
				char *name=RetrieveString(zlib_wrapper);
				if(name)
				{
					ClientAnalysisInfo->address_fingerprint_hash_map.insert(AddressFingerPrintAddress_Pair(address,name));
					ClientAnalysisInfo->fingerprint_hash_map.insert(FingerPrintAddress_Pair(name,address));
					free(name);
				}
				break;
			}
			case TYPE_ADDRESS_NAME_HASH_MAP:
			{
				//multimap <DWORD,string> address_name_hash_map;
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					&address,
					sizeof(address)); 
				char *name=RetrieveString(zlib_wrapper);
				if(name)
				{
					ClientAnalysisInfo->address_name_hash_map.insert(AddressName_Pair(address,name));
					//ClientAnalysisInfo->name_hash_map.insert(NameAddress_Pair((name,address));
					free(name);
				}
				break;
			}
			case TYPE_MAP_INFO_HASH_MAP:
			{
				//multimap <DWORD,PMapInfo> map_info_hash_map;
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					&address,
					sizeof(address)); 
				PMapInfo p_map_info=new MapInfo;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *) 
					p_map_info,
					sizeof(MapInfo)); 
				ClientAnalysisInfo->map_info_hash_map.insert(AddrPMapInfo_Pair(address,p_map_info));
				break;
			}
		}
	}
	for(int i=0;i<10;i++)
		if(TypesCount[i])
			if(DebugLevel&1) dprintf("%s: ID=%d %u\n",GetFileDataTypeStr(i),TypesCount[i]);
	delete zlib_wrapper;
	//DumpAnalysisInfo();
	//GenerateTwoLevelFingerPrint();
#endif
	return TRUE;
}

int ReadMapInfoCallback(void *arg,int argc,char **argv,char **names)
{
	//printf("%s: %s %s %s %s\n",__FUNCTION__,m_FileID,argv[0],argv[1],argv[2],argv[3]);
	AnalysisInfo *ClientAnalysisInfo=(AnalysisInfo *)arg;

	PMapInfo p_map_info=new MapInfo;
	p_map_info->Type=strtoul10(argv[0]);
	p_map_info->SrcBlock=strtoul10(argv[1]);
	p_map_info->SrcBlockEnd=strtoul10(argv[2]);
	p_map_info->Dst=strtoul10(argv[3]);
#if DEBUG_LEVEL > 1
	if(DebugLevel&1) dprintf("%s: ID=%d strtoul10(%s)=0x%x,strtoul10(%s)=0x%x,strtoul10(%s)=0x%x,strtoul10(%s)=0x%x\n",__FUNCTION__,m_FileID,
		argv[0],strtoul10(argv[0]),
		argv[1],strtoul10(argv[1]),
		argv[2],strtoul10(argv[2]),
		argv[3],strtoul10(argv[3])
		);
#endif
	ClientAnalysisInfo->map_info_hash_map.insert(AddrPMapInfo_Pair(p_map_info->SrcBlock,p_map_info));
	return 0;
}

int ReadOneLocationInfoDataCallback(void *arg,int argc,char **argv,char **names)
{
	AnalysisInfo *ClientAnalysisInfo=(AnalysisInfo *)arg;
	if(argv[1] && argv[1][0]!=NULL)
	{
		DWORD Address=strtoul10(argv[0]);
		unsigned char *FingerprintStr=HexToBytesWithLengthAmble(argv[1]);
		if(FingerprintStr)
			ClientAnalysisInfo->address_fingerprint_hash_map.insert(AddressFingerPrintAddress_Pair(Address,FingerprintStr));
		ClientAnalysisInfo->name_hash_map.insert(NameAddress_Pair(argv[2],Address));
	}
	return 0;
}

BOOL OneIDAClientManager::Retrieve(DBWrapper *InputDB,int FileID,BOOL bRetrieveDataForAnalysis)
{
	m_FileID=FileID;
	m_OutputDB=InputDB;

	m_OutputDB->ExecuteStatement(m_OutputDB->ReadRecordStringCallback,&m_OriginalFilePath,"SELECT OriginalFilePath FROM FileInfo WHERE id=%u",m_FileID);
	ClientAnalysisInfo=new AnalysisInfo;
	m_OutputDB->ExecuteStatement(ReadMapInfoCallback,(void *)ClientAnalysisInfo,"SELECT Type,SrcBlock,SrcBlockEnd,Dst From MapInfo WHERE FileID=%u ORDER BY ID ASC",FileID);
	if(bRetrieveDataForAnalysis)
	{
		RetrieveAnalysisData();
	}
	return TRUE;
}

char *OneIDAClientManager::GetOriginalFilePath()
{
	return m_OriginalFilePath;
}

BOOL OneIDAClientManager::RetrieveAnalysisData()
{
	if(ClientAnalysisInfo->fingerprint_hash_map.size()==0)
	{
		m_OutputDB->ExecuteStatement(ReadOneLocationInfoDataCallback,(void *)ClientAnalysisInfo,"SELECT StartAddress,Fingerprint,Name FROM OneLocationInfo WHERE FileID=%u",m_FileID);
		GenerateFingerprintHashMap();
	}
	return TRUE;
}

typedef struct {
	DWORD address;
	DWORD child_address;
} AddressPair;

void OneIDAClientManager::RetrieveIDARawData(PBYTE (*RetrieveCallback)(PVOID Context,BYTE *Type,DWORD *Length),PVOID Context)
{
	BYTE type;
	DWORD length;

	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	multimap <string, DWORD>::iterator fingerprint_hash_map_pIter;
	multimap <string, DWORD>::iterator name_hash_map_pIter;
	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;

	ClientAnalysisInfo=new AnalysisInfo;
	DWORD current_addr=0L;

	m_OutputDB->BeginTransaction();
	while(1)
	{	
		PBYTE data=RetrieveCallback(Context,&type,&length);
#if DEBUG_LEVEL > 0
		if(DebugLevel&1) dprintf("%s: ID=%d type=%u Data(0x%x) is Read %u Bytes Long\n",__FUNCTION__,m_FileID,type,data,length);
#endif

		if(type==END_OF_DATA)
		{
#if DEBUG_LEVEL > -1
			if(DebugLevel&1) dprintf("%s: ID=%d End of Analysis\n",__FUNCTION__);
			if(DebugLevel&1) dprintf("%s: ID=%d address_hash_map:%u/address_fingerprint_hash_map:%u/fingerprint_hash_map:%u/name_hash_map:%u/map_info_hash_map:%u\n",
				__FUNCTION__,m_FileID,
				ClientAnalysisInfo->address_hash_map.size(),
				ClientAnalysisInfo->address_fingerprint_hash_map.size(),
				ClientAnalysisInfo->fingerprint_hash_map.size(),
				ClientAnalysisInfo->name_hash_map.size(),
				ClientAnalysisInfo->map_info_hash_map.size()
			);
#endif
			if(data)
				free(data);
			break;
		}
		if(!data)
			continue;
		m_FileID=DatabaseWriterWrapper(m_OutputDB,type,data,length);
		if(type==ONE_LOCATION_INFO && sizeof(OneLocationInfo)<=length)
		{
			POneLocationInfo pOneLocationInfo=(POneLocationInfo)data;
			current_addr=pOneLocationInfo->StartAddress;
			if(DebugLevel&4) dprintf("%s: ID=%d ONE_LOCATION_INFO[StartAddress=%x Flag=%u function addr=%x BlockType=%u]\n",__FUNCTION__,m_FileID,
				pOneLocationInfo->StartAddress,//ea_t
				pOneLocationInfo->Flag, //Flag_t
				pOneLocationInfo->FunctionAddress,
				pOneLocationInfo->BlockType);
#ifdef USE_LEGACY_MAP
			ClientAnalysisInfo->address_hash_map.insert(AddrPOneLocationInfo_Pair(pOneLocationInfo->StartAddress,pOneLocationInfo) );			
#endif
			ClientAnalysisInfo->name_hash_map.insert(NameAddress_Pair(pOneLocationInfo->Data,pOneLocationInfo->StartAddress));
			if(pOneLocationInfo->FingerprintLen>0)
			{
				unsigned char *FingerprintBuffer=(unsigned char *)malloc(pOneLocationInfo->FingerprintLen+sizeof(short));
				*(short *)FingerprintBuffer=pOneLocationInfo->FingerprintLen;
				memcpy(FingerprintBuffer+sizeof(short),pOneLocationInfo->Data+pOneLocationInfo->NameLen+pOneLocationInfo->DisasmLinesLen,*(short *)FingerprintBuffer);
				ClientAnalysisInfo->address_fingerprint_hash_map.insert(AddressFingerPrintAddress_Pair(pOneLocationInfo->StartAddress,FingerprintBuffer));
			}
			free(data);
		}else if(type==MAP_INFO && length==sizeof(MapInfo))
		{
			PMapInfo p_map_info=(PMapInfo)data;
#if DEBUG_LEVEL > 2
			if(DebugLevel&1) dprintf("%s: ID=%d %s %x(%x)->%x\n",__FUNCTION__,m_FileID,
				MapInfoTypesStr[p_map_info->Type],
				p_map_info->SrcBlock,
				p_map_info->SrcBlockEnd,
				p_map_info->Dst);
#endif
			ClientAnalysisInfo->map_info_hash_map.insert(AddrPMapInfo_Pair(p_map_info->SrcBlock,p_map_info));
			/*
			We don't use backward CFG anymore.
			if(p_map_info->Type==CREF_FROM || p_map_info->Type==CALL)
			{
				PMapInfo p_new_map_info=(PMapInfo)malloc(sizeof(MapInfo));
				p_new_map_info->SrcBlock=p_map_info->Dst;
				p_new_map_info->Src=p_map_info->Dst;
				p_new_map_info->Dst=p_map_info->SrcBlock;
				if(p_map_info->Type==CREF_FROM)
					p_new_map_info->Type=CREF_TO;
				else
					p_new_map_info->Type=CALLED;
				ClientAnalysisInfo->map_info_hash_map.insert(AddrPMapInfo_Pair(p_new_map_info->SrcBlock,p_new_map_info));
			}*/
		}else
		{
			free(data);
		}
	}
	m_OutputDB->EndTransaction();
	FixFunctionAddresses();
	GenerateFingerprintHashMap();
}

void OneIDAClientManager::GenerateFingerprintHashMap()
{
	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	list <AddressPair> AddressPairs;
	multimap <DWORD,POneLocationInfo>::iterator iter;
	for(iter=ClientAnalysisInfo->address_hash_map.begin();
		iter!=ClientAnalysisInfo->address_hash_map.end();
		iter++)
	{
		DWORD address=iter->first;
		multimap <DWORD, PMapInfo>::iterator map_info_hash_map_iter;
		int matched_children_count=0;
		DWORD matched_child_addr=0L;
		for(map_info_hash_map_iter=ClientAnalysisInfo->map_info_hash_map.find(address);
			map_info_hash_map_iter!=ClientAnalysisInfo->map_info_hash_map.end();
			map_info_hash_map_iter++
			)
		{
			if(map_info_hash_map_iter->first!=address)
				break;
			PMapInfo p_map_info=map_info_hash_map_iter->second;
			if(p_map_info->Type==CREF_FROM)
			{
				matched_child_addr=map_info_hash_map_iter->second->Dst;
				matched_children_count++;
			}
		}
		if(DebugLevel&1) dprintf("%s: ID=%d 0x%x children count: %u\n",__FUNCTION__,m_FileID,address,matched_children_count);
		if(matched_children_count==1 && matched_child_addr!=0L)
		{
			int matched_parents_count=0;
			for(map_info_hash_map_iter=ClientAnalysisInfo->map_info_hash_map.find(matched_child_addr);
				map_info_hash_map_iter!=ClientAnalysisInfo->map_info_hash_map.end();
				map_info_hash_map_iter++
				)
			{
				if(map_info_hash_map_iter->first!=matched_child_addr)
					break;
				PMapInfo p_map_info=map_info_hash_map_iter->second;
				if(p_map_info->Type==CREF_TO || p_map_info->Type==CALLED)
					matched_parents_count++;
			}
			if(DebugLevel&1) dprintf("%s: ID=%d 0x%x -> 0x%x parent count: %u\n",__FUNCTION__,m_FileID,address,matched_child_addr,matched_parents_count);
			if(matched_parents_count==1)
			{
				address_hash_map_pIter=ClientAnalysisInfo->address_hash_map.find(matched_child_addr);
				if(address_hash_map_pIter!=ClientAnalysisInfo->address_hash_map.end())
				{
					POneLocationInfo pOneLocationInfo=(POneLocationInfo)address_hash_map_pIter->second;
					if(pOneLocationInfo->FunctionAddress!=matched_child_addr)
					{
						AddressPair address_pair;
						address_pair.address=address;
						address_pair.child_address=matched_child_addr;
						AddressPairs.push_back(address_pair);
					}
				}
			}
		}
	}

	list <AddressPair>::iterator AddressPairsIter;
	for(AddressPairsIter=AddressPairs.begin();
		AddressPairsIter!=AddressPairs.end();
		AddressPairsIter++)
	{
		DWORD address=(*AddressPairsIter).address;
		DWORD child_address=(*AddressPairsIter).child_address;
		if(DebugLevel&1) dprintf("%s: ID=%d Joining 0x%x-0x%x\n",__FUNCTION__,m_FileID,address,child_address);

		DWORD matched_child_addr=0L;

		multimap <DWORD, PMapInfo>::iterator map_info_hash_map_iter;
		for(map_info_hash_map_iter=ClientAnalysisInfo->map_info_hash_map.find(child_address);
			map_info_hash_map_iter!=ClientAnalysisInfo->map_info_hash_map.end();
			map_info_hash_map_iter++
			)
		{
			if(map_info_hash_map_iter->first!=child_address)
				break;
			PMapInfo p_map_info=map_info_hash_map_iter->second;
			PMapInfo p_new_map_info=(PMapInfo)malloc(sizeof(MapInfo));
			p_new_map_info->SrcBlockEnd=address;
			p_new_map_info->SrcBlock=address;
			p_new_map_info->Dst=p_map_info->Dst;
			p_new_map_info->Type=p_map_info->Type;
			ClientAnalysisInfo->map_info_hash_map.insert(AddrPMapInfo_Pair(address,p_new_map_info));
		}
		for(map_info_hash_map_iter=ClientAnalysisInfo->map_info_hash_map.find(address);
			map_info_hash_map_iter!=ClientAnalysisInfo->map_info_hash_map.end();
			map_info_hash_map_iter++
			)
		{
			if(map_info_hash_map_iter->first!=address)
				break;
			PMapInfo p_map_info=map_info_hash_map_iter->second;
			if(p_map_info->Dst==child_address)
			{
				ClientAnalysisInfo->map_info_hash_map.erase(map_info_hash_map_iter);
				break;
			}
		}
		multimap <DWORD, string>::iterator child_address_disassembly_hash_map_iter;
		child_address_disassembly_hash_map_iter=ClientAnalysisInfo->address_disassembly_hash_map.find(child_address);
		if(child_address_disassembly_hash_map_iter!=ClientAnalysisInfo->address_disassembly_hash_map.end())
		{
			multimap <DWORD, string>::iterator address_disassembly_hash_map_iter;
			address_disassembly_hash_map_iter=ClientAnalysisInfo->address_disassembly_hash_map.find(address);
			if(address_disassembly_hash_map_iter!=ClientAnalysisInfo->address_disassembly_hash_map.end())
			{
				address_disassembly_hash_map_iter->second+=child_address_disassembly_hash_map_iter->second;
			}
		}

		multimap <DWORD,unsigned char *>::iterator child_address_fingerprint_hash_map_iter;
		child_address_fingerprint_hash_map_iter=ClientAnalysisInfo->address_fingerprint_hash_map.find(child_address);
		if(child_address_fingerprint_hash_map_iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end())
		{
			multimap <DWORD,unsigned char *>::iterator address_fingerprint_hash_map_iter;
			address_fingerprint_hash_map_iter=ClientAnalysisInfo->address_fingerprint_hash_map.find(address);
			if(address_fingerprint_hash_map_iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end())
			{
				//TODO: address_fingerprint_hash_map_iter->second+=child_address_fingerprint_hash_map_iter->second;
			}
		}
		ClientAnalysisInfo->address_hash_map.erase((*AddressPairsIter).child_address);
		ClientAnalysisInfo->address_name_hash_map.erase((*AddressPairsIter).child_address);
		ClientAnalysisInfo->map_info_hash_map.erase((*AddressPairsIter).child_address);
		ClientAnalysisInfo->address_disassembly_hash_map.erase((*AddressPairsIter).child_address);
		ClientAnalysisInfo->address_fingerprint_hash_map.erase((*AddressPairsIter).child_address);
	}
	AddressPairs.clear();

	multimap <DWORD,unsigned char *>::iterator address_fingerprint_hash_map_Iter;
	for(address_fingerprint_hash_map_Iter=ClientAnalysisInfo->address_fingerprint_hash_map.begin();
		address_fingerprint_hash_map_Iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end();
		address_fingerprint_hash_map_Iter++)
	{
		ClientAnalysisInfo->fingerprint_hash_map.insert(FingerPrintAddress_Pair(address_fingerprint_hash_map_Iter->second,address_fingerprint_hash_map_Iter->first));
	}
	GenerateTwoLevelFingerPrint();
}

void OneIDAClientManager::GenerateTwoLevelFingerPrint()
{
	/*
	multimap <unsigned char *,DWORD,hash_compare_fingerprint>::iterator fingerprint_hash_map_pIter;
	for(fingerprint_hash_map_pIter=ClientAnalysisInfo->fingerprint_hash_map.begin();
		fingerprint_hash_map_pIter!=ClientAnalysisInfo->fingerprint_hash_map.end();
		fingerprint_hash_map_pIter++)

	{
		if(ClientAnalysisInfo->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first)>1)
		{
			int addresses_number=0;
			DWORD *addresses=GetMappedAddresses(fingerprint_hash_map_pIter->second,CREF_FROM,&addresses_number);
			if(!addresses)
				addresses=GetMappedAddresses(fingerprint_hash_map_pIter->second,CREF_TO,NULL);
			if(addresses)
			{
				int TwoLevelFingerprintLength=0;
				TwoLevelFingerprintLength+=*(short *)fingerprint_hash_map_pIter->first; //+
				multimap <DWORD, unsigned char *>::iterator address_fingerprint_hash_map_Iter;
				for(int i=0;i<addresses_number;i++)
				{
					address_fingerprint_hash_map_Iter=ClientAnalysisInfo->address_fingerprint_hash_map.find(addresses[i]);
					if(address_fingerprint_hash_map_Iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end())
					{
						TwoLevelFingerprintLength+=*(short *)address_fingerprint_hash_map_Iter->second; //+
					}
				}

				if(TwoLevelFingerprintLength>0)
				{
					unsigned char *TwoLevelFingerprint=(unsigned char *)malloc(TwoLevelFingerprintLength+sizeof(short));
					if(TwoLevelFingerprint)
					{
						*(short *)TwoLevelFingerprint=TwoLevelFingerprintLength;

						int Offset=sizeof(short);
						memcpy(TwoLevelFingerprint+Offset,fingerprint_hash_map_pIter->first+sizeof(short),*(short *)fingerprint_hash_map_pIter->first);
						Offset+=*(short *)fingerprint_hash_map_pIter->first;
						for(int i=0;i<addresses_number;i++)
						{
							address_fingerprint_hash_map_Iter=ClientAnalysisInfo->address_fingerprint_hash_map.find(addresses[i]);
							if(address_fingerprint_hash_map_Iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end())
							{
								memcpy(TwoLevelFingerprint+Offset,address_fingerprint_hash_map_Iter->second+sizeof(short),*(short *)address_fingerprint_hash_map_Iter->second);
								Offset+=*(short *)address_fingerprint_hash_map_Iter->second;
							}
						}
						ClientAnalysisInfo->fingerprint_hash_map.insert(FingerPrintAddress_Pair(TwoLevelFingerprint,fingerprint_hash_map_pIter->second));
					}
				}
			}
		}
	}*/
}

void OneIDAClientManager::DumpAnalysisInfo()
{
	if(ClientAnalysisInfo)
	{
		/*
		if(DebugLevel&1) dprintf("OriginalFilePath=%s\n",ClientAnalysisInfo->file_info.OriginalFilePath);
		if(DebugLevel&1) dprintf("ComputerName=%s\n",ClientAnalysisInfo->file_info.ComputerName);
		if(DebugLevel&1) dprintf("UserName=%s\n",ClientAnalysisInfo->file_info.UserName);
		if(DebugLevel&1) dprintf("CompanyName=%s\n",ClientAnalysisInfo->file_info.CompanyName);
		if(DebugLevel&1) dprintf("FileVersion=%s\n",ClientAnalysisInfo->file_info.FileVersion);
		if(DebugLevel&1) dprintf("FileDescription=%s\n",ClientAnalysisInfo->file_info.FileDescription);
		if(DebugLevel&1) dprintf("InternalName=%s\n",ClientAnalysisInfo->file_info.InternalName);
		if(DebugLevel&1) dprintf("ProductName=%s\n",ClientAnalysisInfo->file_info.ProductName);
		if(DebugLevel&1) dprintf("ModifiedTime=%s\n",ClientAnalysisInfo->file_info.ModifiedTime);
		if(DebugLevel&1) dprintf("MD5Sum=%s\n",ClientAnalysisInfo->file_info.MD5Sum);

		*/
		if(DebugLevel&1) dprintf("fingerprint_hash_map=%u\n",ClientAnalysisInfo->fingerprint_hash_map.size());
	}
}

BOOL OneIDAClientManager::SendTLVData(char type,PBYTE data,DWORD data_length)
{
	if(Socket!=INVALID_SOCKET)
	{
		BOOL ret=::SendTLVData(Socket,
			type,
			data,
			data_length);
		if(!ret)
			Socket=INVALID_SOCKET;
		return ret;
	}
	return FALSE;
}

char *OneIDAClientManager::GetDisasmLines(unsigned long StartAddress,unsigned long EndAddress)
{
#ifdef USE_LEGACY_MAP
	//Look for p_analysis_info->address_disassembly_hash_map first
	multimap <DWORD, string>::iterator address_disassembly_hash_map_pIter;
	address_disassembly_hash_map_pIter=ClientAnalysisInfo->address_disassembly_hash_map.find(StartAddress);
	if(address_disassembly_hash_map_pIter!=ClientAnalysisInfo->address_disassembly_hash_map.end())
	{
		return _strdup(address_disassembly_hash_map_pIter->second.c_str());
	}
	CodeBlock code_block;
	code_block.StartAddress=StartAddress;
	if(Socket==INVALID_SOCKET)
		return strdup("");

	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	if(EndAddress==0)
	{
		address_hash_map_pIter=ClientAnalysisInfo->address_hash_map.find(StartAddress);
		if(address_hash_map_pIter!=ClientAnalysisInfo->address_hash_map.end())
		{
			POneLocationInfo pOneLocationInfo=(POneLocationInfo)address_hash_map_pIter->second;
			EndAddress=pOneLocationInfo->EndAddress;
		}
	}
	code_block.EndAddress=EndAddress;
	DisasmLine=NULL;
	if(SendTLVData(GET_DISASM_LINES,(PBYTE)&code_block,sizeof(code_block)))
	{
		char type;
		DWORD length;
		PBYTE data=RecvTLVData(Socket,&type,&length);
		if(data)
			DisasmLine=(char *)data;
			return (char *)data;
	}
	return strdup("");
#else
	char *DisasmLines=NULL;
	m_OutputDB->ExecuteStatement(m_OutputDB->ReadRecordStringCallback,&DisasmLines,"SELECT DisasmLines FROM OneLocationInfo WHERE FileID=%u and StartAddress=%u",m_FileID,StartAddress);
	if(DisasmLines)
	{
		if(DebugLevel&1) dprintf("DisasmLines=%s\n",DisasmLines);
		return DisasmLines;
	}
	return _strdup("");
#endif
}

int ReadOneLocationInfoCallback(void *arg,int argc,char **argv,char **names)
{
	POneLocationInfo p_one_location_info=(POneLocationInfo)arg;
	p_one_location_info->StartAddress=strtoul10(argv[0]);
	p_one_location_info->EndAddress=strtoul10(argv[1]);
	p_one_location_info->Flag=strtoul10(argv[2]);
	p_one_location_info->FunctionAddress=strtoul10(argv[3]);
	p_one_location_info->BlockType=strtoul10(argv[4]);

	if(DebugLevel&8)
	{		
		dprintf("%s: %x Block Type: %d\n",__FUNCTION__,p_one_location_info->StartAddress,p_one_location_info->BlockType);
	}
	if(DebugLevel&1 && p_one_location_info->BlockType==FUNCTION_BLOCK)
	{		
		dprintf("%s: Function Block: %x\n",__FUNCTION__,p_one_location_info->StartAddress);
	}
	return 0;
}

POneLocationInfo OneIDAClientManager::GetOneLocationInfo(DWORD address)
{
	POneLocationInfo p_one_location_info=(POneLocationInfo)malloc(sizeof(OneLocationInfo));
	m_OutputDB->ExecuteStatement(ReadOneLocationInfoCallback,p_one_location_info,"SELECT StartAddress,EndAddress,Flag,FunctionAddress,BlockType FROM OneLocationInfo WHERE FileID=%u and StartAddress=%u",m_FileID,address);
	return p_one_location_info;
}

void OneIDAClientManager::FreeDisasmLines()
{
	if(DisasmLine)
		free(DisasmLine);
}

void OneIDAClientManager::ShowAddress(unsigned long address)
{
	SendTLVData(JUMP_TO_ADDR,(PBYTE)&address,sizeof(DWORD));
}

list <DWORD> OneIDAClientManager::GetFunctionMemberBlocks(unsigned long address)
{
	list <DWORD> address_list;
	list <DWORD>::iterator address_list_iter;
	hash_set <DWORD> checked_addresses;
	address_list.push_back(address);
	checked_addresses.insert(address);
	for(address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	)
	{
		int addresses_number;
		DWORD *p_addresses=GetMappedAddresses(*address_list_iter,CREF_FROM,&addresses_number);
		if(p_addresses && addresses_number>0)
		{
			for(int i=0;i<addresses_number;i++)
			{
				if(p_addresses[i])
				{
					if(checked_addresses.find(p_addresses[i])==checked_addresses.end())
					{
						address_list.push_back(p_addresses[i]);
						checked_addresses.insert(p_addresses[i]);
					}
				}
			}
			free(p_addresses);
		}
	}
	return address_list;
}

void OneIDAClientManager::MergeBlocks()
{
	multimap <DWORD, PMapInfo>::iterator last_iter=ClientAnalysisInfo->map_info_hash_map.end();
	multimap <DWORD, PMapInfo>::iterator iter;
	multimap <DWORD, PMapInfo>::iterator child_iter;

	int NumberOfChildren=1;
	for(iter=ClientAnalysisInfo->map_info_hash_map.begin();
		iter!=ClientAnalysisInfo->map_info_hash_map.end();
		iter++
		)
	{
		if(iter->second->Type==CREF_FROM)
		{
			BOOL bHasOnlyOneChild=FALSE;
			if(last_iter!=ClientAnalysisInfo->map_info_hash_map.end())
			{
				if(last_iter->first==iter->first)
				{
					NumberOfChildren++;
				}else
				{
					if(DebugLevel&1) dprintf("%s: ID=%d Number Of Children for %x =%u\n",
											__FUNCTION__,m_FileID,
											last_iter->first,
											NumberOfChildren);
					if(NumberOfChildren==1)
						bHasOnlyOneChild=TRUE;
					multimap <DWORD, PMapInfo>::iterator next_iter=iter;
					next_iter++;
					if(next_iter==ClientAnalysisInfo->map_info_hash_map.end())
					{
						last_iter=iter;
						bHasOnlyOneChild=TRUE;
					}
					NumberOfChildren=1;
				}
			}
			if(bHasOnlyOneChild)
			{
				int NumberOfParents=0;
				for(child_iter=ClientAnalysisInfo->map_info_hash_map.find(last_iter->second->Dst);
					child_iter!=ClientAnalysisInfo->map_info_hash_map.end() && child_iter->first==last_iter->second->Dst;
					child_iter++)
				{
					if(child_iter->second->Type==CREF_TO && child_iter->second->Dst!=last_iter->first)
					{
						if(DebugLevel&1) dprintf("%s: ID=%d Found %x -> %x\n",
							__FUNCTION__,m_FileID,
							child_iter->second->Dst,child_iter->first);
						NumberOfParents++;
					}
				}
				if(NumberOfParents==0)
				{
					if(DebugLevel&1) dprintf("%s: ID=%d Found Mergable Nodes %x -> %x\n",
						__FUNCTION__,m_FileID,
						last_iter->first,last_iter->second->Dst);
				}
			}
			last_iter=iter;
		}
	}
}

int OneIDAClientManager::GetFileID()
{
	return m_FileID;
}

unsigned char HexToChar(char *Hex)
{
	int ReturnValue=0;
	for(int i=0;Hex[i] && i<2;i++)
	{
		int CurrentInt=-1;
		char c=Hex[i];
		if('0' <= c && c <='9')
		{
			CurrentInt=c-'0';
		}else if('a' <= c && c <='f')
		{
			CurrentInt=c-'a'+10;
		}else if('A' <= c && c <='F')
		{
			CurrentInt=c-'A'+10;
		}
		if(CurrentInt>=0)
			ReturnValue=ReturnValue*16+CurrentInt;
	}
	return ReturnValue;
}

unsigned char *HexToBytes(char *HexBytes,int *pLen)
{
	int StrLen=strlen(HexBytes);
	*pLen=StrLen/2;
	unsigned char *Bytes=(unsigned char *)malloc(*pLen);
	if(Bytes)
	{
		for(int i=0;i<StrLen;i+=2)
		{
			Bytes[i/2]=HexToChar(HexBytes+i);
		}
	}
	return Bytes;
}

unsigned char *HexToBytesWithLengthAmble(char *HexBytes)
{
	int StrLen=strlen(HexBytes);
	unsigned char *Bytes=(unsigned char *)malloc(StrLen/2+sizeof(short));
	*(short *)Bytes=StrLen/2;
	if(Bytes)
	{
		for(int i=0;i<StrLen;i+=2)
		{
			Bytes[sizeof(short)+i/2]=HexToChar(HexBytes+i);
		}
	}
	return Bytes;
}

char *BytesWithLengthAmbleToHex(unsigned char *Bytes)
{
	int Len=*(short *)Bytes;
	char *Hex=(char *)malloc(Len*2+1);
	Hex[0]=NULL;
	for(int i=0;i<Len;i++)
	{
		char tmp_buffer[10]={0,};
		_snprintf(tmp_buffer,sizeof(tmp_buffer)-1,"%.2x",Bytes[sizeof(short)+i]);
		strcat(Hex,tmp_buffer);
	}
	return Hex;
}

int IsEqualByteWithLengthAmble(unsigned char *Bytes01,unsigned char *Bytes02)
{
	if(*(short *)Bytes01==*(short *)Bytes02)
	{
		return (memcmp(Bytes01+sizeof(short),Bytes02+sizeof(short),*(short *)Bytes01)==0);
	}
	return FALSE;
}

static int ReadFunctionMembersResultsCallback(void *arg,int argc,char **argv,char **names)
{
	hash_set <DWORD> *FunctionAddressHash=(hash_set <DWORD> *)arg;
	if(FunctionAddressHash)
	{
#if DEBUG_LEVEL > 1
		if(DebugLevel&1) dprintf("%s: ID=%d strtoul10(%s)=0x%x\n",__FUNCTION__,m_FileID,argv[0],strtoul10(argv[0]));
#endif
		FunctionAddressHash->insert(strtoul10(argv[0]));
	}
	return 0;
}

multimap <DWORD,DWORD> *OneIDAClientManager::LoadFunctionMembersMap()
{
	if(DebugLevel&1) dprintf("Retrieve Functions Addresses\n");
	list <DWORD> *FunctionAddresses=GetFunctionAddresses();
	if(FunctionAddresses)
	{
		if(DebugLevel&1) dprintf("Retrieved Functions Addresses(%u entries)\n",FunctionAddresses->size());

		multimap <DWORD,DWORD> *FunctionMembers=new multimap <DWORD,DWORD>;
		if(FunctionMembers)
		{
			list <DWORD>::iterator FunctionAddressIter;
			for(FunctionAddressIter=FunctionAddresses->begin();FunctionAddressIter!=FunctionAddresses->end();FunctionAddressIter++)
			{
				if(DebugLevel&1) dprintf("Function %x: ",*FunctionAddressIter);
				list <DWORD> FunctionMemberBlocks=GetFunctionMemberBlocks(*FunctionAddressIter);
				list <DWORD>::iterator FunctionMemberBlocksIter;

				for(FunctionMemberBlocksIter=FunctionMemberBlocks.begin();
					FunctionMemberBlocksIter!=FunctionMemberBlocks.end();
					FunctionMemberBlocksIter++
				)
				{
					if(DebugLevel&1) dprintf("%x ",*FunctionMemberBlocksIter);
					FunctionMembers->insert(pair <DWORD,DWORD>(*FunctionAddressIter,*FunctionMemberBlocksIter));
				}
				if(DebugLevel&1) dprintf("\n");
			}
		}

		/*
		multimap <DWORD,DWORD>::iterator FunctionMembersIter;
		DWORD FunctionAddress=0;
		for(FunctionMembersIter=FunctionMembers->begin();FunctionMembersIter!=FunctionMembers->end();FunctionMembersIter++)
		{
			if(FunctionAddress!=FunctionMembersIter->first)
			{
				FunctionAddress=FunctionMembersIter->first;
				if(DebugLevel&1) dprintf("%x\n",FunctionAddress);
			}
			if(DebugLevel&1) dprintf("\t%x\n",FunctionMembersIter->second);
		}
		*/
		FunctionAddresses->clear();
		delete FunctionAddresses;
		return FunctionMembers;
	}
	return NULL;
}

static int ReadAddressToFunctionMapResultsCallback(void *arg,int argc,char **argv,char **names)
{
	hash_map <DWORD,DWORD> *AddressToFunctionMap=(hash_map <DWORD,DWORD> *)arg;
	if(AddressToFunctionMap)
	{
#if DEBUG_LEVEL > 1
		if(DebugLevel&1) dprintf("%s: ID=%d strtoul10(%s)=0x%x,strtoul10(%s)=0x%x\n",__FUNCTION__,m_FileID,argv[0],strtoul10(argv[0]),argv[1],strtoul10(argv[1]));
#endif
		AddressToFunctionMap->insert(pair <DWORD,DWORD>(strtoul10(argv[0]),strtoul10(argv[1])));
	}
	return 0;
}

list <DWORD> *OneIDAClientManager::GetFunctionAddresses()
{
	int DoCrefFromCheck=FALSE;
	int DoCallCheck=TRUE;
	hash_set <DWORD> FunctionAddressHash;
	hash_map <DWORD,short> AddressesHash;

	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;
	if(DoCrefFromCheck)
	{
		if(DebugLevel&1) dprintf("AddressesHash.size()=%u\n",AddressesHash.size());
		for(map_info_hash_map_pIter=ClientAnalysisInfo->map_info_hash_map.begin();
			map_info_hash_map_pIter!=ClientAnalysisInfo->map_info_hash_map.end();
			map_info_hash_map_pIter++
			)
		{
			if(DebugLevel&1) dprintf("%X-%X(%s) ",map_info_hash_map_pIter->first,map_info_hash_map_pIter->second->Dst,MapInfoTypesStr[map_info_hash_map_pIter->second->Type]);
			if(map_info_hash_map_pIter->second->Type==CREF_FROM)
			{
				hash_map <DWORD,short>::iterator iter=AddressesHash.find(map_info_hash_map_pIter->second->Dst);
				if(iter!=AddressesHash.end())
				{
					iter->second=FALSE;
				}
			}
		}
		if(DebugLevel&1) dprintf("%s\n",__FUNCTION__);
		multimap <DWORD, unsigned char *>::iterator address_fingerprint_hash_map_iter;
		for(address_fingerprint_hash_map_iter=ClientAnalysisInfo->address_fingerprint_hash_map.begin();
			address_fingerprint_hash_map_iter!=ClientAnalysisInfo->address_fingerprint_hash_map.end();
			address_fingerprint_hash_map_iter++)
		{
			AddressesHash.insert(pair<DWORD,short>(address_fingerprint_hash_map_iter->first,DoCrefFromCheck?TRUE:FALSE));
		}
		if(DebugLevel&1) dprintf("AddressesHash.size()=%u\n",AddressesHash.size());
		for(hash_map <DWORD,short>::iterator AddressesHashIterator=AddressesHash.begin();AddressesHashIterator!=AddressesHash.end();AddressesHashIterator++)
		{
			if(AddressesHashIterator->second)
			{
				if(DebugLevel&1) dprintf("%s: ID=%d Function %X\n",__FUNCTION__,m_FileID,AddressesHashIterator->first);
				FunctionAddressHash.insert(AddressesHashIterator->first);
			}
		}
	}else
	{
		m_OutputDB->ExecuteStatement(ReadFunctionMembersResultsCallback,&FunctionAddressHash,"SELECT DISTINCT(FunctionAddress) FROM OneLocationInfo WHERE FileID=%u AND BlockType=%u",m_FileID,FUNCTION_BLOCK);
	}

	if(DoCallCheck)
	{
		for(map_info_hash_map_pIter=ClientAnalysisInfo->map_info_hash_map.begin();
			map_info_hash_map_pIter!=ClientAnalysisInfo->map_info_hash_map.end();
			map_info_hash_map_pIter++
			)
		{
			if(map_info_hash_map_pIter->second->Type==CALL)
			{
				if(FunctionAddressHash.find(map_info_hash_map_pIter->second->Dst)==FunctionAddressHash.end())
				{
					if(DebugLevel&1)
						dprintf("%s: ID=%d Function %X (by Call Recognition)\n",__FUNCTION__,m_FileID,map_info_hash_map_pIter->second->Dst);
					FunctionAddressHash.insert(map_info_hash_map_pIter->second->Dst);
				}
			}
		}
	}

	list <DWORD> *FunctionAddresses=new list<DWORD>;
	if(FunctionAddresses)
	{
		for(hash_set <DWORD>::iterator FunctionAddressHashIter=FunctionAddressHash.begin();
			FunctionAddressHashIter!=FunctionAddressHash.end();
			FunctionAddressHashIter++)
		{
			FunctionAddresses->push_back(*FunctionAddressHashIter);
			if(DebugLevel&4)
				dprintf("%s: ID=%d Function %X\n",__FUNCTION__,m_FileID,*FunctionAddressHashIter);
		}
		if(DebugLevel&1) dprintf("%s: ID=%d Returns(%u entries)\n",__FUNCTION__,m_FileID,FunctionAddresses->size());
	}
	return FunctionAddresses;
}

multimap <DWORD,DWORD> *OneIDAClientManager::LoadAddressToFunctionMap()
{
	int Count=0;
	if(DebugLevel&1) dprintf("%s: ID=%d GetFunctionAddresses\n",__FUNCTION__);
	list <DWORD> *FunctionAddresses=GetFunctionAddresses();
	if(FunctionAddresses)
	{
		if(DebugLevel&1) dprintf("%s: ID=%d Function %u entries\n",__FUNCTION__,m_FileID,FunctionAddresses->size());
		multimap <DWORD,DWORD> *AddressToFunctionMap=new multimap <DWORD,DWORD>;
		if(AddressToFunctionMap)
		{
			list <DWORD>::iterator FunctionAddressIter;
			for(FunctionAddressIter=FunctionAddresses->begin();FunctionAddressIter!=FunctionAddresses->end();FunctionAddressIter++)
			{
				list <DWORD> FunctionMemberBlocks=GetFunctionMemberBlocks(*FunctionAddressIter);
				list <DWORD>::iterator FunctionMemberBlocksIter;

				for(FunctionMemberBlocksIter=FunctionMemberBlocks.begin();
					FunctionMemberBlocksIter!=FunctionMemberBlocks.end();
					FunctionMemberBlocksIter++
				)
				{
					AddressToFunctionMap->insert(pair <DWORD,DWORD>(*FunctionMemberBlocksIter,*FunctionAddressIter));
				}
			}
		}
		FunctionAddresses->clear();
		delete FunctionAddresses;
		if(DebugLevel&1) dprintf("%s: ID=%d AddressToFunctionMap %u entries\n",__FUNCTION__,m_FileID,AddressToFunctionMap->size());
		return AddressToFunctionMap;
		/*
		hash_map <DWORD,DWORD>::iterator AddressToFunctionMapIter;
		DWORD FunctionAddress=0;
		for(AddressToFunctionMapIter=AddressToFunctionMap->begin();AddressToFunctionMapIter!=AddressToFunctionMap->end();AddressToFunctionMapIter++)
		{
			if(FunctionAddress!=AddressToFunctionMapIter->first)
			{
				FunctionAddress=AddressToFunctionMapIter->first;
				if(DebugLevel&1) dprintf("%x\n",FunctionAddress);
			}
			if(DebugLevel&1) dprintf("\t%x\n",AddressToFunctionMapIter->second);
		}*/

	}
	return NULL;
}

void OneIDAClientManager::FixFunctionAddresses()
{
	if(DebugLevel&1) dprintf("%s",__FUNCTION__);
	multimap <DWORD,DWORD> *AddressToFunctionMap=LoadAddressToFunctionMap();
	multimap <DWORD,DWORD>::iterator AddressToFunctionMapIter;
	m_OutputDB->BeginTransaction();
	for(AddressToFunctionMapIter=AddressToFunctionMap->begin();AddressToFunctionMapIter!=AddressToFunctionMap->end();AddressToFunctionMapIter++)
	{
		//StartAddress: AddressToFunctionMapIter->first
		//FunctionAddress: AddressToFunctionMapIter->second
		//Update
		if(DebugLevel&1) 
			dprintf("Updating OneLocationInfoTable Address=%x Function=%x\r\n",
				AddressToFunctionMapIter->second,
				AddressToFunctionMapIter->first);

		m_OutputDB->ExecuteStatement(NULL,NULL,UPDATE_ONE_LOCATION_INFO_TABLE_FUNCTION_ADDRESS_STATEMENT,
					AddressToFunctionMapIter->second,
					AddressToFunctionMapIter->second==AddressToFunctionMapIter->first?FUNCTION_BLOCK:UNKNOWN_BLOCK,
					m_FileID,
					AddressToFunctionMapIter->first);
	}
	if(DebugLevel&1) dprintf("\r\n");

	m_OutputDB->EndTransaction();
	AddressToFunctionMap->clear();
	delete AddressToFunctionMap;
}
