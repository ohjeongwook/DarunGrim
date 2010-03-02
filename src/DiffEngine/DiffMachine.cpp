#include "DiffMachine.h"
#include <string>
#include <list>
#include <hash_set>
#include <hash_map>
#include "ZlibWrapper.h"
#include "Diff.h"
#include "dprintf.h"

#define strtoul10(X) strtoul(X,NULL,10)

#define DEBUG_LEVEL 2

using namespace std;
using namespace stdext;
#include "Configuration.h"

char *MatchDataTypeStr[]={"Name Match","Fingerprint Match","Two Level Fingerprint Match","Tree Match"};

#include "sqlite3.h"

extern int DebugLevel;

DiffMachine::DiffMachine(OneIDAClientManager *the_source,OneIDAClientManager *the_target)
{
	m_InputDB=NULL;
	m_TheSourceFileID=0;
	m_TheTargetFileID=0;
	TheSource=NULL;
	TheTarget=NULL;
	DiffResults=NULL;
	SetOneIDAClientManagers(the_source,the_target);
}

void DiffMachine::SetOneIDAClientManagers(OneIDAClientManager *the_source,OneIDAClientManager *the_target)
{
	TheSource=the_source;
	TheTarget=the_target;
}

OneIDAClientManager *DiffMachine::GetTheSource()
{
	return TheSource;
}

OneIDAClientManager *DiffMachine::GetTheTarget()
{
	return TheTarget;
}

int DiffMachine::GetFingerPrintMatchRate(unsigned char* unpatched_finger_print,unsigned char* patched_finger_print)
{
	int rate=0;
	char *unpatched_finger_print_str=BytesWithLengthAmbleToHex(unpatched_finger_print);
	if(unpatched_finger_print_str)
	{
		char *patched_finger_print_str=BytesWithLengthAmbleToHex(patched_finger_print);
		if(patched_finger_print_str)
		{		
			rate=GetStringSimilarity(unpatched_finger_print_str,patched_finger_print_str);
			free(unpatched_finger_print_str);
		}
		free(patched_finger_print_str);
	}
	return rate;
}

int DiffMachine::GetMatchRate(DWORD unpatched_address,DWORD patched_address)
{
	multimap <DWORD, unsigned char *>::iterator unpatched_address_fingerprint_hash_map_Iter;
	multimap <DWORD, unsigned char *>::iterator patched_address_fingerprint_hash_map_Iter;
						
	unpatched_address_fingerprint_hash_map_Iter=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(unpatched_address);
	patched_address_fingerprint_hash_map_Iter=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(patched_address);

	if(
		unpatched_address_fingerprint_hash_map_Iter!=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
		patched_address_fingerprint_hash_map_Iter!=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() 
	)
	{
		return GetFingerPrintMatchRate(
			unpatched_address_fingerprint_hash_map_Iter->second,
			patched_address_fingerprint_hash_map_Iter->second);
	}
	return 0;
}

void DiffMachine::DumpMatchMapIterInfo(const char *prefix,multimap <DWORD, MatchData>::iterator match_map_iter)
{
	char *SubTypeStr[]={"Cref From","Cref To","Call","Dref From","Dref To"};	
	if(DebugLevel>=0)
		dprintf("%s: match: %x - %x (%s/%s) from: %x %x (Match rate=%u/100) Status=%x\n",
			prefix,
			match_map_iter->first,
			match_map_iter->second.Addresses[1],
			MatchDataTypeStr[match_map_iter->second.Type],
			(match_map_iter->second.Type==TREE_MATCH && match_map_iter->second.SubType<sizeof(SubTypeStr)/sizeof(char *))?SubTypeStr[match_map_iter->second.SubType]:"None",
			match_map_iter->second.UnpatchedParentAddress,
			match_map_iter->second.PatchedParentAddress,
			match_map_iter->second.MatchRate,
			match_map_iter->second.Status);
}

void DiffMachine::AnalyzeFunctionSanity()
{
	multimap <DWORD, MatchData>::iterator last_match_map_iter;
	multimap <DWORD, MatchData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	DWORD unpatched_addr=0;
	DWORD patched_addr=0;

	if(DebugLevel&1)
		dprintf("%s: DiffResults->MatchMap Size=%u\n",__FUNCTION__,DiffResults->MatchMap.size());	
	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
#ifdef USE_LEGACY_MAP
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=TheSource->GetClientAnalysisInfo()->address_hash_map.find(match_map_iter->first);
		if(address_hash_map_pIter!=TheSource->GetClientAnalysisInfo()->address_hash_map.end())
		{
			POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
		POneLocationInfo p_one_location_info=TheSource->GetOneLocationInfo(match_map_iter->first);
		if(p_one_location_info)
		{
#endif
			unpatched_addr=match_map_iter->first;
			patched_addr=match_map_iter->second.Addresses[1];
			if(last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr
			)
			{
				if(p_one_location_info->BlockType==FUNCTION_BLOCK)
				{
				}else
				{
				}
			}
			if(last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			)
			{
				if(DebugLevel&1)
					dprintf("%s: **** Multiple Possibilities\n",__FUNCTION__);
				DumpMatchMapIterInfo("",last_match_map_iter);
				DumpMatchMapIterInfo("",match_map_iter);
			}

			last_match_map_iter=match_map_iter;
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;
#ifndef USE_LEGACY_MAP
			free(p_one_location_info);
#endif
		}
	}

	hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator;
	for(reverse_match_map_iterator=DiffResults->ReverseAddressMap.begin();
		reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end();
		reverse_match_map_iterator++)
	{
#ifdef USE_LEGACY_MAP
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=TheTarget->GetClientAnalysisInfo()->address_hash_map.find(reverse_match_map_iterator->first);

		if(address_hash_map_pIter!=TheTarget->GetClientAnalysisInfo()->address_hash_map.end())
		{
			POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
		POneLocationInfo p_one_location_info=TheSource->GetOneLocationInfo(reverse_match_map_iterator->first);
		if(p_one_location_info)
		{			
#endif
			unpatched_addr=reverse_match_map_iterator->first;
			patched_addr=reverse_match_map_iterator->second;
			
			if(last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr)
			{
				if(p_one_location_info->BlockType==FUNCTION_BLOCK)
				{
				}else
				{
				}
			}
			if(last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			)
			{
				if(DebugLevel&1)
					dprintf("%s: **** Multiple Possibilities\n",__FUNCTION__);
				//DumpMatchMapIterInfo("",match_map_iter);
			}else
			{
			}
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;
		}
	}
}
	
bool DiffMachine::Analyze()
{
	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	multimap <string, DWORD>::iterator fingerprint_hash_map_pIter;
	multimap <string, DWORD>::iterator name_hash_map_pIter;
	multimap <DWORD, PMapInfo>::iterator map_info_hash_map_pIter;
	multimap <DWORD,MatchData> TemporaryMatchMap;

	if(!TheSource || !TheTarget)
		return FALSE;

	TheSource->FixFunctionAddresses();
	TheSource->RetrieveAnalysisData();

	TheTarget->FixFunctionAddresses();
	TheTarget->RetrieveAnalysisData();
	DiffResults=new AnalysisResult;
	if(DebugLevel&1)
		dprintf("%s: Fingerprint Map Size %u:%u\n",__FUNCTION__,
			TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.size(),
			TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.size());

	FunctionMembersMapForTheSource=TheSource->LoadFunctionMembersMap();
	FunctionMembersMapForTheTarget=TheTarget->LoadFunctionMembersMap();
	AddressToFunctionMapForTheSource=TheSource->LoadAddressToFunctionMap();
	AddressToFunctionMapForTheTarget=TheTarget->LoadAddressToFunctionMap();

	// Name Match
	multimap <string, DWORD>::iterator patched_name_hash_map_pIter;
	for(name_hash_map_pIter=TheSource->GetClientAnalysisInfo()->name_hash_map.begin();
		name_hash_map_pIter!=TheSource->GetClientAnalysisInfo()->name_hash_map.end();
		name_hash_map_pIter++)
	{
		if(TheSource->GetClientAnalysisInfo()->name_hash_map.count(name_hash_map_pIter->first)==1)
		{
			//unique key
			if(TheTarget->GetClientAnalysisInfo()->name_hash_map.count(name_hash_map_pIter->first)==1)
			{
				if(name_hash_map_pIter->first.find("loc_")!=string::npos || 
					name_hash_map_pIter->first.find("locret_")!=string::npos ||
					name_hash_map_pIter->first.find("sub_")!=string::npos ||
					name_hash_map_pIter->first.find("func_")!=string::npos)
					continue;
				patched_name_hash_map_pIter=TheTarget->GetClientAnalysisInfo()->name_hash_map.find(name_hash_map_pIter->first);
				if(patched_name_hash_map_pIter!=TheTarget->GetClientAnalysisInfo()->name_hash_map.end())
				{
					MatchData match_data;
					memset(&match_data,0,sizeof(MatchData));
					match_data.Type=NAME_MATCH;
					match_data.Addresses[0]=name_hash_map_pIter->second;
					match_data.Addresses[1]=patched_name_hash_map_pIter->second;
					match_data.MatchRate=GetMatchRate(
						name_hash_map_pIter->second,
						patched_name_hash_map_pIter->second
						);

					TemporaryMatchMap.insert(MatchMap_Pair(
						name_hash_map_pIter->second,
						match_data
						));
					if(DebugLevel&1)
						dprintf("%s: matched %s(%x)-%s(%x) MatchRate=%u%%\n",__FUNCTION__,
							name_hash_map_pIter->first.c_str(),
							name_hash_map_pIter->second,
							patched_name_hash_map_pIter->first.c_str(),
							patched_name_hash_map_pIter->second,
							match_data.MatchRate);
				}
			}
		}
	}
	if(DebugLevel&1)
		dprintf("%s: Name matched number=%u\n",__FUNCTION__,TemporaryMatchMap.size());

	int OldMatchMapSize=0;
	while(1)
	{
		if(DebugLevel&1)
			dprintf("%s: DoFingerPrintMatch\n",__FUNCTION__);
		DoFingerPrintMatch(&TemporaryMatchMap);
		if(DebugLevel&1)
			dprintf("%s: Match Map Size: %u\n",__FUNCTION__,TemporaryMatchMap.size());

		if(DebugLevel&1)
			dprintf("%s: DoIsomorphMatch\n",__FUNCTION__);
		DoIsomorphMatch(&TemporaryMatchMap);

		if(DebugLevel&1)
			dprintf("%s: Match Map Size: %u\n",__FUNCTION__,TemporaryMatchMap.size());

		if(TemporaryMatchMap.size()>0)
		{
			AppendToMatchMap(&DiffResults->MatchMap,&TemporaryMatchMap);
		}else
		{
			break;
		}
		PurgeFingerprintHashMap(&TemporaryMatchMap);
		TemporaryMatchMap.clear();

		if(DebugLevel&1)
			dprintf("%s: Call DoFunctionMatch\n",__FUNCTION__);
		DoFunctionMatch(&DiffResults->MatchMap,&TemporaryMatchMap);

		if(DebugLevel&1)
			dprintf("%s: One Loop Of Analysis MatchMap size is %u.\n",__FUNCTION__,DiffResults->MatchMap.size());
		if(OldMatchMapSize==DiffResults->MatchMap.size())
			break;
		OldMatchMapSize=DiffResults->MatchMap.size();
	}
	//Construct reverse_match_map
	for(multimap <DWORD, MatchData>::iterator match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		DiffResults->ReverseAddressMap.insert(pair<DWORD,DWORD>(match_map_iter->second.Addresses[1],match_map_iter->first));
	}
	//RemoveDuplicates();
	//AnalyzeFunctionSanity();
	GenerateFunctionMatchInfo();

	FunctionMembersMapForTheSource->clear();
	delete FunctionMembersMapForTheSource;
	FunctionMembersMapForTheSource=NULL;

	FunctionMembersMapForTheTarget->clear();
	delete FunctionMembersMapForTheTarget;
	FunctionMembersMapForTheTarget=NULL;

	AddressToFunctionMapForTheSource->clear();
	delete AddressToFunctionMapForTheSource;
	AddressToFunctionMapForTheSource=NULL;

	AddressToFunctionMapForTheTarget->clear();
	delete AddressToFunctionMapForTheTarget;
	AddressToFunctionMapForTheTarget=NULL;
	return true;
}

void DiffMachine::AppendToMatchMap(multimap <DWORD,MatchData> *pBaseMap,multimap <DWORD,MatchData> *pTemporaryMap)
{
	multimap <DWORD, MatchData>::iterator match_map_iter;
	if(DebugLevel&1)
		dprintf("%s: Appending %u Items To MatchMap\n",__FUNCTION__,pTemporaryMap->size());
	for(match_map_iter=pTemporaryMap->begin();
		match_map_iter!=pTemporaryMap->end();
		match_map_iter++)
	{
		pBaseMap->insert(MatchMap_Pair(match_map_iter->first,match_map_iter->second));
	}
}

void DiffMachine::PurgeFingerprintHashMap(multimap <DWORD,MatchData> *pTemporaryMap)
{
	multimap <DWORD, MatchData>::iterator match_map_iter;
	if(DebugLevel&1)
		dprintf("%s: Delete %u Items from Fingerprint Map(%u-%u)\n",__FUNCTION__,pTemporaryMap->size(),
			TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.size(),
			TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.size());
	for(match_map_iter=pTemporaryMap->begin();
		match_map_iter!=pTemporaryMap->end();
		match_map_iter++)
	{
		//Remove from fingerprint hash map
		multimap <DWORD, unsigned char *>::iterator address_fingerprint_hash_map_Iter;
		address_fingerprint_hash_map_Iter=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(match_map_iter->second.Addresses[0]);
		if(address_fingerprint_hash_map_Iter!=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
		{
			TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.erase(address_fingerprint_hash_map_Iter->second);
		}
		address_fingerprint_hash_map_Iter=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(match_map_iter->second.Addresses[1]);
		if(address_fingerprint_hash_map_Iter!=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
		{
			TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.erase(address_fingerprint_hash_map_Iter->second);
		}
	}
	if(DebugLevel&1)
		dprintf("%s: %u-%u\n",__FUNCTION__,
			TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.size(),
			TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.size());
}

void DiffMachine::DoFingerPrintMatch(multimap <DWORD,MatchData> *p_match_map)
{
	multimap <unsigned char *,DWORD,hash_compare_fingerprint>::iterator fingerprint_hash_map_pIter;
	multimap <unsigned char *, DWORD,hash_compare_fingerprint>::iterator patched_fingerprint_hash_map_pIter;

	for(fingerprint_hash_map_pIter=TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.begin();
		fingerprint_hash_map_pIter!=TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.end();
		fingerprint_hash_map_pIter++)
	{
		if(TheSource->GetClientAnalysisInfo()->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first)==1)
		{
			//unique key
			if(TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first)==1)
			{
				patched_fingerprint_hash_map_pIter=TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.find(fingerprint_hash_map_pIter->first);
				if(patched_fingerprint_hash_map_pIter!=TheTarget->GetClientAnalysisInfo()->fingerprint_hash_map.end())
				{
					MatchData match_data;
					memset(&match_data,0,sizeof(MatchData));
					match_data.Type=FINGERPRINT_MATCH;
					match_data.Addresses[0]=fingerprint_hash_map_pIter->second;
					match_data.Addresses[1]=patched_fingerprint_hash_map_pIter->second;
					match_data.MatchRate=100;
					p_match_map->insert(MatchMap_Pair(
						fingerprint_hash_map_pIter->second,
						match_data
						));
				}
			}
		}
	}

	if(DebugLevel&1)
		dprintf("%s: Matched pair count=%u\n",__FUNCTION__,p_match_map->size());
}

void DiffMachine::DoIsomorphMatch(multimap <DWORD,MatchData> *pOrigTemporaryMap)
{
	multimap <DWORD,MatchData> *pTemporaryMap=pOrigTemporaryMap;
	int types[]={CREF_FROM,CALL,DREF_FROM}; //CREF_TO,DREF_TO

	while(pTemporaryMap->size()>0)
	{
		int processed_count=0;
		multimap <DWORD, MatchData>::iterator match_map_iter;
		multimap <DWORD,MatchData> *pNewTemporaryMap=new multimap <DWORD,MatchData>;

		if(DebugLevel&1)
			dprintf("%s: Tree Match count=%u\n",__FUNCTION__,pTemporaryMap->size());
		for(match_map_iter=pTemporaryMap->begin();
			match_map_iter!=pTemporaryMap->end();
			match_map_iter++)
		{
			int unpatched_addresses_number;
			int patched_addresses_number;

			for(int type_pos=0;type_pos<sizeof(types)/sizeof(int);type_pos++)
			{
				DWORD *unpatched_addresses=TheSource->GetMappedAddresses(match_map_iter->first,types[type_pos],&unpatched_addresses_number);
				DWORD *patched_addresses=TheTarget->GetMappedAddresses(match_map_iter->second.Addresses[1],types[type_pos],&patched_addresses_number);
				if(DebugLevel&4)
					dprintf("%s: Tree Matching Mapped Address Count: %x(%x) %x(%x) ",__FUNCTION__,
						unpatched_addresses_number,match_map_iter->first,
						patched_addresses_number,match_map_iter->second.Addresses[1]);
				if(DebugLevel&8)
				{
					int i;
					dprintf("%s: %u %x-%x\n\t",__FUNCTION__,types[type_pos],match_map_iter->first,match_map_iter->second.Addresses[1]);
					for(i=0;i<unpatched_addresses_number;i++)
						dprintf("%x ",unpatched_addresses[i]);
					dprintf("\n\t");
					for(i=0;i<patched_addresses_number;i++)
						dprintf("%x ",patched_addresses[i]);
					dprintf("\n");
				}

				if(unpatched_addresses_number==patched_addresses_number)
				{
					multimap <DWORD, unsigned char *>::iterator unpatched_address_fingerprint_hash_map_Iter;
					multimap <DWORD, unsigned char *>::iterator patched_address_fingerprint_hash_map_Iter;
					
					for(int i=0;i<unpatched_addresses_number;i++)
					{
						unpatched_address_fingerprint_hash_map_Iter=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(unpatched_addresses[i]);
						patched_address_fingerprint_hash_map_Iter=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(patched_addresses[i]);
							
						int MatchRate=100;
						if(
							(
								(
									unpatched_address_fingerprint_hash_map_Iter!=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
									patched_address_fingerprint_hash_map_Iter!=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() 
								) &&
								(MatchRate=GetFingerPrintMatchRate(
									unpatched_address_fingerprint_hash_map_Iter->second,
									patched_address_fingerprint_hash_map_Iter->second))
							) ||
							(
								unpatched_address_fingerprint_hash_map_Iter==TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
								patched_address_fingerprint_hash_map_Iter==TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end()
							)
						)
						{
							bool add=TRUE;
							multimap <DWORD,MatchData> *p_compared_match_map[]={
								&DiffResults->MatchMap,
								pOrigTemporaryMap,
								pNewTemporaryMap,
								pTemporaryMap};
							
							multimap <DWORD, MatchData>::iterator cur_match_map_iter;
							//If not found from "all" match map
							for(int compare_i=0;compare_i<sizeof(p_compared_match_map)/sizeof(p_compared_match_map[0]);compare_i++)
							{
								cur_match_map_iter=p_compared_match_map[compare_i]->find(unpatched_addresses[i]);

								while(cur_match_map_iter!=p_compared_match_map[compare_i]->end() &&
										cur_match_map_iter->first==unpatched_addresses[i]
								)
								{
									if(cur_match_map_iter->second.Addresses[1]==patched_addresses[i])
									{
										if(DebugLevel&2)
											dprintf("Match is already there %x-%x\n",unpatched_addresses[i],patched_addresses[i]);
										add=FALSE;
										break;
									}else if(MatchRate<cur_match_map_iter->second.MatchRate)
									{
										if(DebugLevel&2)
											dprintf("Another match is already there with higher match rate %x-%x(%u%%)\n",
												unpatched_addresses[i],
												cur_match_map_iter->second.Addresses[1]);
										add=FALSE;
										break;
									}
									cur_match_map_iter++;
								}
								if(!add)
									break;
							}
							if(add)
							{
								if(DebugLevel&2)
									dprintf("Adding %x-%x\n",unpatched_addresses[i],patched_addresses[i]);
								MatchData match_data;
								memset(&match_data,0,sizeof(MatchData));
								match_data.Type=TREE_MATCH;
								match_data.SubType=type_pos;
								match_data.Addresses[0]=unpatched_addresses[i];
								match_data.Addresses[1]=patched_addresses[i];
								match_data.MatchRate=MatchRate;
								match_data.UnpatchedParentAddress=match_map_iter->first;
								match_data.PatchedParentAddress=match_map_iter->second.Addresses[1];
								pNewTemporaryMap->insert(MatchMap_Pair(
									unpatched_addresses[i],
									match_data
									));
							}
							{
								
							}
						}
						if(DebugLevel&2)
							dprintf("MatchRate=%u%%\n",MatchRate);
					}
				}
				if(unpatched_addresses)
					free(unpatched_addresses);
				if(patched_addresses)
					free(patched_addresses);
			}
			processed_count++;

			if(DebugLevel&4)
			{
				if(processed_count%100==0 || processed_count==pTemporaryMap->size())
				{
					dprintf("%s: %u/%u Items processed and produced %u match entries.\n",__FUNCTION__,
						processed_count,
						pTemporaryMap->size(),
						pNewTemporaryMap->size()
					);
				}
			}
		}

		dprintf("%s: New Tree Match count=%u\n",__FUNCTION__,pNewTemporaryMap->size());
		if(pNewTemporaryMap->size()>0)
		{
			AppendToMatchMap(pOrigTemporaryMap,pNewTemporaryMap);
			if(pTemporaryMap!=pOrigTemporaryMap)
			{
				pTemporaryMap->clear();
				delete pTemporaryMap;
			}
			pTemporaryMap=pNewTemporaryMap;
		}else
		{
			pNewTemporaryMap->clear();
			delete pNewTemporaryMap;
			break;
		}
	}
}

void DiffMachine::DoFunctionMatch(multimap <DWORD,MatchData> *pTemporaryMap,multimap <DWORD,MatchData> *pTargetTemporaryMap)
{
	multimap <DWORD,DWORD>::iterator FunctionMembersIter;
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	multimap <DWORD,DWORD>::iterator SourceFunctionMembersIter;
	DWORD SourceFunctionAddress=0;
	list <DWORD> SourceBlockAddresses;
	for(SourceFunctionMembersIter=FunctionMembersMapForTheSource->begin();;SourceFunctionMembersIter++)
	{
		if(SourceFunctionMembersIter==FunctionMembersMapForTheSource->end() || SourceFunctionAddress!=SourceFunctionMembersIter->first)
		{
			//SourceFunctionAddress,SourceBlockAddresses
			hash_set <DWORD> TargetFunctionAddresses;
			for(multimap <DWORD, MatchData>::iterator MatchMapIter=pTemporaryMap->find(SourceFunctionAddress);MatchMapIter!=pTemporaryMap->end();MatchMapIter++)
			{
				if(MatchMapIter->first!=SourceFunctionAddress)
				{
					break;
				}
				//TargetFunctionAddress,TargetBlockAddresses
				DWORD TargetFunctionAddress=MatchMapIter->second.Addresses[1];
				if(TargetFunctionAddresses.find(TargetFunctionAddress)==TargetFunctionAddresses.end())
					continue;

				TargetFunctionAddresses.insert(TargetFunctionAddress);
				multimap <DWORD,DWORD>::iterator TargetFunctionMembersIter;
				list <DWORD> TargetBlockAddresses;
				for(TargetFunctionMembersIter=FunctionMembersMapForTheTarget->find(TargetFunctionAddress);
					TargetFunctionMembersIter!=FunctionMembersMapForTheTarget->end() &&
					TargetFunctionMembersIter->first==TargetFunctionAddress;
					TargetFunctionMembersIter++)
				{
					TargetBlockAddresses.push_back(TargetFunctionMembersIter->second);
				}
				//,
				DoFingerPrintMatchInsideFunction(pTemporaryMap,SourceFunctionAddress,SourceBlockAddresses,TargetFunctionAddress,TargetBlockAddresses);
				TargetBlockAddresses.clear();
			}
			TargetFunctionAddresses.clear();
			SourceBlockAddresses.clear();
			if(SourceFunctionMembersIter==FunctionMembersMapForTheSource->end())
				break;
			else
				SourceFunctionAddress=SourceFunctionMembersIter->first;
		}
		SourceBlockAddresses.push_back(SourceFunctionMembersIter->second);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hash_map <DWORD,DWORD> FunctionsMatchCounts;
	list <DWORD> BlockAddresses;
	DWORD TheSourceFunctionAddress=0;
	for(FunctionMembersIter=FunctionMembersMapForTheSource->begin();;FunctionMembersIter++)
	{
		if(FunctionMembersIter==FunctionMembersMapForTheSource->end() || TheSourceFunctionAddress!=FunctionMembersIter->first)
		{
			//Analyze Function,BlockAddresses contains all the members
			//
			if(TheSourceFunctionAddress!=0)
			{
				list <DWORD>::iterator BlockAddressesIter;
				for(BlockAddressesIter=BlockAddresses.begin();BlockAddressesIter!=BlockAddresses.end();BlockAddressesIter++)
				{
					DWORD Address=*BlockAddressesIter;
					if(DebugLevel&2)
						dprintf("Function %X-Basic Block %X\r\n",TheSourceFunctionAddress,Address);
					for(multimap <DWORD, MatchData>::iterator MatchMapIter=pTemporaryMap->find(Address);
						MatchMapIter!=pTemporaryMap->end() && MatchMapIter->first==Address;
						MatchMapIter++)
					{
						multimap <DWORD,DWORD>::iterator AddressToFunctionMapForTheTargetIter=AddressToFunctionMapForTheTarget->find(MatchMapIter->second.Addresses[1]);
						if(AddressToFunctionMapForTheTargetIter!=AddressToFunctionMapForTheTarget->end())
						{
							DWORD MatchedFunctionAddress=AddressToFunctionMapForTheTargetIter->second;
							hash_map <DWORD,DWORD>::iterator FunctionsMatchCountsIter;

							//AddressToFunctionMap.insert(pair<DWORD,DWORD>(Address,MatchedFunctionAddress));
							FunctionsMatchCountsIter=FunctionsMatchCounts.find(MatchedFunctionAddress);
							if(FunctionsMatchCountsIter==FunctionsMatchCounts.end())
							{
								FunctionsMatchCounts.insert(pair<DWORD,DWORD>(MatchedFunctionAddress,1));
							}else
							{
								FunctionsMatchCountsIter->second++;
							}
						}
					}
				}
				//TheSourceFunctionAddress
				//We have FunctionsMatchCounts filled up!
				//Get Maximum value in FunctionsMatchCounts
				hash_map <DWORD,DWORD>::iterator FunctionsMatchCountsIter;
				DWORD MaximumEntries=0;
				DWORD TheChosenTargetFunctionAddress=0;
				for(FunctionsMatchCountsIter=FunctionsMatchCounts.begin();FunctionsMatchCountsIter!=FunctionsMatchCounts.end();FunctionsMatchCountsIter++)
				{
					if(DebugLevel&2)
						dprintf("%x:%x(%u) ",TheSourceFunctionAddress,FunctionsMatchCountsIter->first,FunctionsMatchCountsIter->second);
					if(MaximumEntries<FunctionsMatchCountsIter->second)
					{
						TheChosenTargetFunctionAddress=FunctionsMatchCountsIter->first;
						MaximumEntries=FunctionsMatchCountsIter->second;
					}
				}
				if(TheChosenTargetFunctionAddress)
				{
					//Remove Except TheChosenTargetFunctionAddress from match_map
					if(DebugLevel&2)
						dprintf("=> (%x:%x)\n",TheSourceFunctionAddress,TheChosenTargetFunctionAddress);
					if(pTemporaryMap->find(TheSourceFunctionAddress)==pTemporaryMap->end())
					{
						MatchData match_data;
						memset(&match_data,0,sizeof(MatchData));
						match_data.Type=FUNCTION_MATCH;
						match_data.Addresses[0]=TheSourceFunctionAddress;
						match_data.Addresses[1]=TheChosenTargetFunctionAddress;
						match_data.MatchRate=100;
						pTargetTemporaryMap->insert(MatchMap_Pair(
							TheSourceFunctionAddress,
							match_data
							));
					}
					for(BlockAddressesIter=BlockAddresses.begin();BlockAddressesIter!=BlockAddresses.end();BlockAddressesIter++)
					{
						DWORD Address=*BlockAddressesIter;
						for(multimap <DWORD, MatchData>::iterator MatchMapIter=pTemporaryMap->find(Address);MatchMapIter!=pTemporaryMap->end();)
						{
							if(MatchMapIter->first!=Address)
								break;

							multimap <DWORD,DWORD>::iterator AddressToFunctionMapForTheSourceIter=AddressToFunctionMapForTheSource->find(Address);
							multimap <DWORD,DWORD>::iterator AddressToFunctionMapForTheTargetIter;
							DWORD MatchedAddress=MatchMapIter->second.Addresses[1];
							BOOL Remove=FALSE;
							if(AddressToFunctionMapForTheSourceIter!=AddressToFunctionMapForTheSource->end())
							{
								for(AddressToFunctionMapForTheTargetIter=AddressToFunctionMapForTheTarget->find(MatchedAddress);
									AddressToFunctionMapForTheTargetIter!=AddressToFunctionMapForTheTarget->end();
									AddressToFunctionMapForTheTargetIter++)
								{
									if(AddressToFunctionMapForTheTargetIter->first!=MatchedAddress)
										break;
									if(AddressToFunctionMapForTheTargetIter->second==TheChosenTargetFunctionAddress)
									{
										Remove=FALSE;
										break;
									}else
									{
										Remove=TRUE;
									}
								}
							}

							if(Remove)
							{
									//Remove Address from DiffResults->MatchMap
									if(DebugLevel&2)
										dprintf("Removing address %x(%x)-%x(%x)\n",Address,AddressToFunctionMapForTheSourceIter->second,MatchedAddress,AddressToFunctionMapForTheTargetIter->second);
									MatchMapIter=pTemporaryMap->erase(MatchMapIter);

							}else
							{
								//printf("Keeping address %x(%x)-%x(%x)\n",Address,AddressToFunctionMapForTheSourceIter->second,MatchedAddress,AddressToFunctionMapForTheTargetIter->second);
								MatchMapIter++;
							}
						}
					}
					if(DebugLevel&2)
						dprintf("\n");
				}

				BlockAddresses.clear();
				FunctionsMatchCounts.clear();
				//AddressToFunctionMap.clear();
			}

			if(FunctionMembersIter==FunctionMembersMapForTheSource->end())
				break;
			else
				TheSourceFunctionAddress=FunctionMembersIter->first;
		}
		if(FunctionMembersIter==FunctionMembersMapForTheSource->end())
			break;

		//Collect BlockAddresses
		BlockAddresses.push_back(FunctionMembersIter->second);
	}
}

typedef struct _AddressesInfo_
{
	int Overflowed;
	DWORD TheSourceAddress;
	DWORD TheTargetAddress;
} AddressesInfo;

void DiffMachine::DoFingerPrintMatchInsideFunction(multimap <DWORD,MatchData> *pTemporaryMap,DWORD SourceFunctionAddress,list <DWORD> &SourceBlockAddresses,DWORD TargetFunctionAddress,list <DWORD> &TargetBlockAddresses)
{
	//Fingerprint match on SourceBlockAddresses,TargetBlockAddresse
	/*
	list <DWORD>::iterator SourceBlockAddressIter;
	for(SourceBlockAddressIter=SourceBlockAddresses.begin();SourceBlockAddressIter!=SourceBlockAddresses.end();SourceBlockAddressIter++)
	{
		DWORD SourceAddress=*SourceBlockAddressIter;
		multimap <DWORD,MatchData>:: MatchDataIterator;
		MatchDataIterator=pTemporaryMap->find(SourceAddress);
		if(MatchDataIterator!=pTemporaryMap->end())
		{
			DWORD TargetAddress=MatchDataIterator->second.Addresses[1];
			TargetBlockAddresse.erase(TargetAddress);
		}
	}*/
	//printf("%s: Entry\n",__FUNCTION__);
	multimap <DWORD, unsigned char *>::iterator address_fingerprint_hash_map_Iter;
	hash_map <unsigned char *,AddressesInfo,hash_compare_fingerprint> fingerprint_hash_map;
	hash_map <unsigned char *,AddressesInfo,hash_compare_fingerprint>::iterator fingerprint_hash_map_iter;

	list <DWORD>::iterator SourceBlockAddressIter;
	for(SourceBlockAddressIter=SourceBlockAddresses.begin();SourceBlockAddressIter!=SourceBlockAddresses.end();SourceBlockAddressIter++)
	{
		DWORD SourceAddress=*SourceBlockAddressIter;
		//printf("\tSource=%X\n",SourceAddress);
		address_fingerprint_hash_map_Iter=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(SourceAddress);
		if(address_fingerprint_hash_map_Iter!=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
		{
			unsigned char *FingerPrint=address_fingerprint_hash_map_Iter->second;
			fingerprint_hash_map_iter=fingerprint_hash_map.find(FingerPrint);
			if(fingerprint_hash_map_iter!=fingerprint_hash_map.end())
			{
				fingerprint_hash_map_iter->second.Overflowed=TRUE;
			}else
			{
				AddressesInfo OneAddressesInfo;
				OneAddressesInfo.Overflowed=FALSE;
				OneAddressesInfo.TheSourceAddress=SourceAddress;
				OneAddressesInfo.TheTargetAddress=0L;
				fingerprint_hash_map.insert(pair<unsigned char *,AddressesInfo>(FingerPrint,OneAddressesInfo));
			}
		}
	}
	list <DWORD>::iterator TargetBlockAddressIter;
	for(TargetBlockAddressIter=TargetBlockAddresses.begin();TargetBlockAddressIter!=TargetBlockAddresses.end();TargetBlockAddressIter++)
	{
		DWORD TargetAddress=*TargetBlockAddressIter;
		//printf("\tTarget=%X\n",TargetAddress);
		address_fingerprint_hash_map_Iter=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(TargetAddress);
		if(address_fingerprint_hash_map_Iter!=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
		{
			unsigned char *FingerPrint=address_fingerprint_hash_map_Iter->second;
			fingerprint_hash_map_iter=fingerprint_hash_map.find(FingerPrint);
			if(fingerprint_hash_map_iter!=fingerprint_hash_map.end())
			{
				if(fingerprint_hash_map_iter->second.TheTargetAddress!=0L)
					fingerprint_hash_map_iter->second.Overflowed=TRUE;
				else
					fingerprint_hash_map_iter->second.TheTargetAddress=TargetAddress;
			}else
			{
				AddressesInfo OneAddressesInfo;
				OneAddressesInfo.Overflowed=FALSE;
				OneAddressesInfo.TheSourceAddress=0L;
				OneAddressesInfo.TheTargetAddress=TargetAddress;
				fingerprint_hash_map.insert(pair<unsigned char *,AddressesInfo>(FingerPrint,OneAddressesInfo));
			}
		}
	}
	for(fingerprint_hash_map_iter=fingerprint_hash_map.begin();
		fingerprint_hash_map_iter!=fingerprint_hash_map.end();
		fingerprint_hash_map_iter++)
	{
		if(!fingerprint_hash_map_iter->second.Overflowed &&
			fingerprint_hash_map_iter->second.TheSourceAddress!=0L &&
			fingerprint_hash_map_iter->second.TheTargetAddress!=0L)
		{
			//printf("%s: %x %x\n",__FUNCTION__,fingerprint_hash_map_iter->second.TheSourceAddress,fingerprint_hash_map_iter->second.TheTargetAddress);
			//We found matching blocks
			//fingerprint_hash_map_iter->second.TheSourceAddress,fingerprint_hash_map_iter->second.TheTargetAddress
			MatchData match_data;
			memset(&match_data,0,sizeof(MatchData));
			match_data.Type=FINGERPRINT_INSIDE_FUNCTION_MATCH;
			match_data.Addresses[0]=fingerprint_hash_map_iter->second.TheSourceAddress;
			match_data.Addresses[1]=fingerprint_hash_map_iter->second.TheTargetAddress;

			match_data.UnpatchedParentAddress=SourceFunctionAddress;
			match_data.PatchedParentAddress=TargetFunctionAddress;
			match_data.MatchRate=100;
			pTemporaryMap->insert(MatchMap_Pair(
				fingerprint_hash_map_iter->second.TheSourceAddress,
				match_data
				));
		}
	}
	fingerprint_hash_map.clear();
}

void DiffMachine::PrintMatchMapInfo()
{
	multimap <DWORD, MatchData>::iterator match_map_iter;
	int unique_match_count=0;
	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		if(DiffResults->MatchMap.count(match_map_iter->first)==1)
			unique_match_count++;
	}
	if(DebugLevel&1)
		dprintf("%s: unique_match_count=%u\n",__FUNCTION__,unique_match_count);


	//Print Summary
	//TODO: DiffResults->MatchMap -> save to database...
	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		if(DebugLevel&1)
			dprintf("%s: %x-%x (%s)\n",__FUNCTION__,
		match_map_iter->first,
		match_map_iter->second.Addresses[1],
		MatchDataTypeStr[match_map_iter->second.Type]);
	}

	if(DebugLevel&1)
		dprintf("%s: ** unidentified(0)\n",__FUNCTION__);
	int unpatched_unidentified_number=0;
	multimap <DWORD, unsigned char *>::iterator unpatched_address_fingerprint_hash_map_Iter;
	for(unpatched_address_fingerprint_hash_map_Iter=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		unpatched_address_fingerprint_hash_map_Iter!=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		unpatched_address_fingerprint_hash_map_Iter++
	)
	{
		if(DiffResults->MatchMap.find(unpatched_address_fingerprint_hash_map_Iter->first)==DiffResults->MatchMap.end())
		{
			if(DebugLevel&1)
			{
				dprintf("%s: %x ",__FUNCTION__,unpatched_address_fingerprint_hash_map_Iter->first);
				if(unpatched_unidentified_number%8==7)
					dprintf("\n");
			}
			unpatched_unidentified_number++;
		}
	}
	if(DebugLevel&1)
		dprintf("%s: unpatched_unidentified_number=%u\n",__FUNCTION__,unpatched_unidentified_number);


	if(DebugLevel&1)
		dprintf("%s: ** unidentified(1)\n",__FUNCTION__);
	int patched_unidentified_number=0;
	multimap <DWORD, unsigned char *>::iterator patched_address_fingerprint_hash_map_Iter;
	for(patched_address_fingerprint_hash_map_Iter=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		patched_address_fingerprint_hash_map_Iter!=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		patched_address_fingerprint_hash_map_Iter++
	)
	{
		if(DiffResults->ReverseAddressMap.find(patched_address_fingerprint_hash_map_Iter->first)==DiffResults->ReverseAddressMap.end())
		{
			if(DebugLevel&1) dprintf("%s: %x ",__FUNCTION__,patched_address_fingerprint_hash_map_Iter->first);
			if(patched_unidentified_number%8==7)
				if(DebugLevel&1) dprintf("\n");
			patched_unidentified_number++;
		}
	}
	if(DebugLevel&1) dprintf("%s: patched_unidentified_number=%u\n",__FUNCTION__,patched_unidentified_number);
}


void DiffMachine::ShowDiffMap(DWORD unpatched_address,DWORD patched_address)
{
	DWORD *p_addresses;

	list <DWORD> address_list;
	list <DWORD>::iterator address_list_iter;
	hash_set <DWORD> checked_addresses;
	address_list.push_back(unpatched_address);
	checked_addresses.insert(unpatched_address);

	for(address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	)
	{
		int addresses_number;
		if(DebugLevel&1)
			dprintf("%s:  address=%x\n",__FUNCTION__,*address_list_iter);
		p_addresses=TheSource->GetMappedAddresses(*address_list_iter,CREF_FROM,&addresses_number);
		if(p_addresses && addresses_number>0)
		{
			if(DebugLevel&1)
				dprintf("%s:  p_addresses=%x addresses_number=%u\n",__FUNCTION__,p_addresses,addresses_number);
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
}

void DiffMachine::GetMatchStatistics(
	DWORD address,
	OneIDAClientManager *ClientManager,
	int index,
	int *p_found_match_number,
	int *p_found_match_with_difference_number,
	int *p_not_found_match_number
	)
{
	list <DWORD> address_list=ClientManager->GetFunctionMemberBlocks(address);
	list <DWORD>::iterator address_list_iter;

	(*p_found_match_number)=0;
	(*p_not_found_match_number)=0;
	(*p_found_match_with_difference_number)=0;
	for(address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	)
	{
		MatchData *pMatchData=GetMatchData(index,*address_list_iter);
		if(pMatchData)
		{
			if(pMatchData->MatchRate==100)
			{
				(*p_found_match_number)++;
			}else
			{
				(*p_found_match_with_difference_number)++;
			}
		}else
		{
			(*p_not_found_match_number)++;
		}
	}
}

int DiffMachine::GetFunctionMatchInfoCount()
{
	DWORD size_to_return=FunctionMatchInfoList.size();
	if(DebugLevel&1) dprintf("%s: size_to_return=%u\n",__FUNCTION__,size_to_return);
	return size_to_return;
}

FunctionMatchInfo DiffMachine::GetFunctionMatchInfo(int i)
{
	return FunctionMatchInfoList.at(i);
}

BOOL DiffMachine::IsInUnidentifiedBlockHash(int index,DWORD address)
{
	if(index==0)
		return TheSourceUnidentifedBlockHash.find(address)!=TheSourceUnidentifedBlockHash.end();
	else
		return TheTargetUnidentifedBlockHash.find(address)!=TheTargetUnidentifedBlockHash.end();
}

int DiffMachine::GetUnidentifiedBlockCount(int index)
{
	if(index==0)
		return TheSourceUnidentifedBlockHash.size();
	else
		return TheTargetUnidentifedBlockHash.size();
}

CodeBlock DiffMachine::GetUnidentifiedBlock(int index,int i)
{
	/*
	if(index==0)
		return TheSourceUnidentifedBlockHash.at(i);
	else
		return TheTargetUnidentifedBlockHash.at(i);
		*/

	CodeBlock x;
	memset(&x,0,sizeof(x));
	return x;
}

void DiffMachine::RevokeTreeMatchMapIterInfo(DWORD address,DWORD match_address)
{
	return;
	multimap <DWORD, MatchData>::iterator match_map_iter;
	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		if(match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
			continue;
		if(match_map_iter->second.Type==TREE_MATCH)
		{
			if(match_map_iter->second.UnpatchedParentAddress==address && match_map_iter->second.PatchedParentAddress==match_address)
			{
				match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
				RevokeTreeMatchMapIterInfo(match_map_iter->first,match_map_iter->second.Addresses[1]);
			}
		}
	}
}

void DiffMachine::RemoveDuplicates()
{
	multimap <DWORD, MatchData>::iterator current_map_iter;
	multimap <DWORD, MatchData>::iterator match_map_iter;
	multimap <DWORD, MatchData>::iterator found_match_map_iter;
	multimap <DWORD, MatchData>::iterator max_match_map_iter;
	if(!DiffResults ||! TheSource ||!TheTarget)
		return;

	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		if(match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
			continue;
		int found_duplicate=FALSE;
		max_match_map_iter=match_map_iter;
		int maximum_matchrate=match_map_iter->second.MatchRate;
		for(found_match_map_iter=DiffResults->MatchMap.find(match_map_iter->first);
			found_match_map_iter!=DiffResults->MatchMap.end() &&
			match_map_iter->first==found_match_map_iter->first;
			found_match_map_iter++)
		{
			if(!(found_match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
				&&match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1])
			{
				//Duplicates found
				if(maximum_matchrate<=found_match_map_iter->second.MatchRate)
				{
					found_duplicate=TRUE;
					max_match_map_iter=found_match_map_iter;
					maximum_matchrate=found_match_map_iter->second.MatchRate;
				}
			}
		}
		/*
		if(found_duplicate)
		{
			if(DebugLevel&1) dprintf("%s: Choosing %x %x match\n",__FUNCTION__,max_match_map_iter->first,max_match_map_iter->second.Addresses[1]);
			DumpMatchMapIterInfo(__FUNCTION__,max_match_map_iter);
			for(found_match_map_iter=DiffResults->MatchMap.find(match_map_iter->first);
				found_match_map_iter!=DiffResults->MatchMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++)
			{
				if(max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1])
				{
					if(DebugLevel&1) dprintf("%s: Removing %x %x match\n",__FUNCTION__,found_match_map_iter->first,found_match_map_iter->second.Addresses[1]);
					DumpMatchMapIterInfo(__FUNCTION__,found_match_map_iter);
					found_match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
					RevokeTreeMatchMapIterInfo(found_match_map_iter->first,found_match_map_iter->second.Addresses[1]);

					hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator=DiffResults->ReverseAddressMap.find(found_match_map_iter->second.Addresses[1]);
					if(reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end() && reverse_match_map_iterator->second.Address==found_match_map_iter->first)
					{
						iter->second.Status|=STATUS_MAPPING_DISABLED;
						RevokeTreeMatchMapIterInfo(iter->first,iter->second.Address);
					}
				}
			}
		}*/
	}

	/*CLEAN UP
	hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator;
	for(reverse_match_map_iterator=DiffResults->ReverseAddressMap.begin();
		reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end();
		reverse_match_map_iterator++)
	{
		if(match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
			continue;
		int found_duplicate=FALSE;
		max_match_map_iter=match_map_iter;
		int maximum_matchrate=match_map_iter->second.MatchRate;
		hash_map <DWORD,DWORD>::iterator found_reverse_match_map_iterator;
		for(found_match_map_iter=DiffResults->ReverseAddressMap.find(match_map_iter->first);
			found_match_map_iter!=DiffResults->ReverseAddressMap.end() &&
			match_map_iter->first==found_match_map_iter->first;
			found_match_map_iter++)
		{
			if(!(found_match_map_iter->second.Status&STATUS_MAPPING_DISABLED) &&
				match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1])
			{
				//Duplicates found
				if(maximum_matchrate<found_match_map_iter->second.MatchRate)
				{
					found_duplicate=TRUE;
					max_match_map_iter=found_match_map_iter;
					maximum_matchrate=found_match_map_iter->second.MatchRate;
				}
			}
		}
		if(found_duplicate)
		{
			if(DebugLevel&1) dprintf("%s: Choosing(reverse) %x %x match\n",__FUNCTION__,max_match_map_iter->first,max_match_map_iter->second.Addresses[1]);
			DumpMatchMapIterInfo(__FUNCTION__,max_match_map_iter);
			hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator;
			for(found_match_map_iter=DiffResults->ReverseAddressMap.find(match_map_iter->first);
				found_match_map_iter!=DiffResults->ReverseAddressMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++)
			{
				if(max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1])
				{
					if(DebugLevel&1) dprintf("%s: Removing(reverse) %x:%x match\n",__FUNCTION__,
							found_match_map_iter->first,found_match_map_iter->second.Addresses[1]);
					DumpMatchMapIterInfo(__FUNCTION__,found_match_map_iter);
					found_match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
					RevokeTreeMatchMapIterInfo(found_match_map_iter->second.Addresses[1],found_match_map_iter->first);
					multimap <DWORD, MatchData>::iterator iter=DiffResults->MatchMap.find(found_match_map_iter->second.Addresses[1]);
					for(;iter!=DiffResults->MatchMap.end() && iter->first==found_match_map_iter->second.Addresses[1];iter++)
					{
						if(iter->second.Address==found_match_map_iter->first)
						{
							iter->second.Status|=STATUS_MAPPING_DISABLED;
							RevokeTreeMatchMapIterInfo(iter->second.Address,iter->first);
						}
					}
				}
			}
		}
	}
	*/

	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		)
	{
		if(match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
		{
			current_map_iter=match_map_iter;
			match_map_iter++;
			DiffResults->MatchMap.erase(current_map_iter);
			continue;
		}
		match_map_iter++;
	}
	/*
	hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator;
	for(match_map_iter=DiffResults->ReverseAddressMap.begin();
		match_map_iter!=DiffResults->ReverseAddressMap.end();
		)
	{
		if(match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
		{
			current_map_iter=match_map_iter;
			match_map_iter++;
			DiffResults->ReverseAddressMap.erase(current_map_iter);
			continue;
		}
		match_map_iter++;
	}*/
}

void DiffMachine::GenerateFunctionMatchInfo()
{
	multimap <DWORD, MatchData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	FunctionMatchInfo match_info;

	if(!DiffResults ||! TheSource ||!TheTarget)
		return;

	FunctionMatchInfoList.clear();
	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		if(match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
		{
			if(DebugLevel&2)
				dprintf("%s: Skipping %x %x\n",__FUNCTION__,match_map_iter->first,match_map_iter->second.Addresses[1]);
			continue;
		}
#ifdef USE_LEGACY_MAP
		multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter=TheSource->GetClientAnalysisInfo()->address_hash_map.find(match_map_iter->first);
		if(address_hash_map_pIter!=TheSource->GetClientAnalysisInfo()->address_hash_map.end())
		{
			POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
		POneLocationInfo p_one_location_info=TheSource->GetOneLocationInfo(match_map_iter->first);

		if(DebugLevel&4)
			dprintf("%s: 0x%X Block Type: %d\n",__FUNCTION__,
				match_map_iter->first,
				p_one_location_info?p_one_location_info->BlockType:-1);

		if(p_one_location_info && p_one_location_info->BlockType==FUNCTION_BLOCK)
		{
#endif
			match_info.TheSourceAddress=match_map_iter->first;
			match_info.BlockType=p_one_location_info->BlockType;
			match_info.EndAddress=p_one_location_info->EndAddress;
			match_info.Type=match_map_iter->second.Type;
			match_info.TheTargetAddress=match_map_iter->second.Addresses[1];
			match_info.MatchRate=match_map_iter->second.MatchRate;

			if(last_unpatched_addr!=match_info.TheSourceAddress &&
				last_patched_addr!=match_info.TheTargetAddress
			)
			{
				match_info.TheSourceFunctionName=TheSource->GetName(match_info.TheSourceAddress);
				match_info.TheTargetFunctionName=TheTarget->GetName(match_info.TheTargetAddress);
				GetMatchStatistics(
					match_info.TheSourceAddress,
					TheSource,
					0,
					&match_info.MatchCountForTheSource,
					&match_info.MatchCountWithModificationForTheSource,
					&match_info.NoneMatchCountForTheSource
				);

				GetMatchStatistics(
					match_info.TheTargetAddress,
					TheTarget,
					1,
					&match_info.MatchCountForTheTarget,
					&match_info.MatchCountWithModificationForTheTarget,
					&match_info.NoneMatchCountForTheTarget
				);
				FunctionMatchInfoList.push_back(match_info);
			}
			last_unpatched_addr=match_info.TheSourceAddress;
			last_patched_addr=match_info.TheTargetAddress;
#ifndef USE_LEGACY_MAP
			free(p_one_location_info);
#endif
		}
	}
	if(DebugLevel&1) dprintf("%s: FunctionMatchInfoList.size()=%u\n",__FUNCTION__,FunctionMatchInfoList.size());
	//////////// Unidentifed Locations

	multimap <DWORD, POneLocationInfo>::iterator address_hash_map_pIter;
	int unpatched_unidentified_number=0;
	multimap <DWORD, unsigned char *>::iterator unpatched_address_fingerprint_hash_map_Iter;
	for(unpatched_address_fingerprint_hash_map_Iter=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		unpatched_address_fingerprint_hash_map_Iter!=TheSource->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		unpatched_address_fingerprint_hash_map_Iter++
	)
	{
		if(DiffResults->MatchMap.find(unpatched_address_fingerprint_hash_map_Iter->first)==DiffResults->MatchMap.end())
		{
#ifdef USE_LEGACY_MAP
			address_hash_map_pIter=TheSource->GetClientAnalysisInfo()->address_hash_map.find(unpatched_address_fingerprint_hash_map_Iter->first);
			if(address_hash_map_pIter!=TheSource->GetClientAnalysisInfo()->address_hash_map.end())
			{
				POneLocationInfo p_one_location_info=(POneLocationInfo)p_one_location_info;
#else
			POneLocationInfo p_one_location_info=TheSource->GetOneLocationInfo(unpatched_address_fingerprint_hash_map_Iter->first);
			if(p_one_location_info)
			{
#endif

				if(p_one_location_info->BlockType==FUNCTION_BLOCK)
				{
					match_info.TheSourceAddress=p_one_location_info->StartAddress;
					match_info.TheSourceFunctionName=TheSource->GetName(match_info.TheSourceAddress);
					match_info.BlockType=p_one_location_info->BlockType;
					match_info.EndAddress=p_one_location_info->EndAddress;
					match_info.Type=0;
					match_info.TheTargetAddress=0;
					match_info.TheTargetFunctionName="";
					match_info.MatchRate=0;
					match_info.MatchCountForTheSource=0;
					match_info.MatchCountWithModificationForTheSource=0;
					match_info.NoneMatchCountForTheSource=0;

					match_info.MatchCountForTheTarget=0;
					match_info.MatchCountWithModificationForTheTarget=0;
					match_info.NoneMatchCountForTheTarget=0;

					FunctionMatchInfoList.push_back(match_info);
				}
				TheSourceUnidentifedBlockHash.insert(p_one_location_info->StartAddress);
#ifndef USE_LEGACY_MAP
				free(p_one_location_info);
#endif
			}
			//if(unpatched_unidentified_number%8==7)
			//	if(DebugLevel&1) dprintf("\n");
			unpatched_unidentified_number++;
		}
	}
	if(DebugLevel&1) dprintf("%s: unpatched_unidentified_number=%u\n",__FUNCTION__,TheSourceUnidentifedBlockHash.size());

	int patched_unidentified_number=0;
	multimap <DWORD, unsigned char *>::iterator patched_address_fingerprint_hash_map_Iter;
	for(patched_address_fingerprint_hash_map_Iter=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		patched_address_fingerprint_hash_map_Iter!=TheTarget->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		patched_address_fingerprint_hash_map_Iter++
	)
	{
		if(DiffResults->ReverseAddressMap.find(patched_address_fingerprint_hash_map_Iter->first)==DiffResults->ReverseAddressMap.end())
		{
			//if(DebugLevel&1) dprintf("%s: %x \n",__FUNCTION__,patched_address_fingerprint_hash_map_Iter->first);

#ifdef USE_LEGACY_MAP
			address_hash_map_pIter=TheTarget->GetClientAnalysisInfo()->address_hash_map.find(patched_address_fingerprint_hash_map_Iter->first);
			if(address_hash_map_pIter!=TheTarget->GetClientAnalysisInfo()->address_hash_map.end())
			{
				POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
			POneLocationInfo p_one_location_info=TheTarget->GetOneLocationInfo(patched_address_fingerprint_hash_map_Iter->first);
			if(p_one_location_info)
			{
#endif
				if(p_one_location_info->BlockType==FUNCTION_BLOCK)
				{
					match_info.TheSourceAddress=0;
					match_info.TheSourceFunctionName="";
					match_info.BlockType=p_one_location_info->BlockType;
					match_info.EndAddress=0;
					match_info.Type=0;
					match_info.TheTargetAddress=p_one_location_info->StartAddress;
					match_info.TheTargetFunctionName=TheTarget->GetName(match_info.TheTargetAddress);
					match_info.MatchRate=0;
					match_info.MatchCountForTheSource=0;
					match_info.MatchCountWithModificationForTheSource=0;
					match_info.NoneMatchCountForTheSource=0;

					match_info.MatchCountForTheTarget=0;
					match_info.MatchCountWithModificationForTheTarget=0;
					match_info.NoneMatchCountForTheTarget=0;

					FunctionMatchInfoList.push_back(match_info);
				}

				TheTargetUnidentifedBlockHash.insert(p_one_location_info->StartAddress);
#ifndef USE_LEGACY_MAP
				free(p_one_location_info);
#endif
			}
			//if(patched_unidentified_number%8==7)
			//	if(DebugLevel&1) dprintf("\n");
			patched_unidentified_number++;
		}
	}
	if(DebugLevel&1) dprintf("%s: patched_unidentified_number=%u\n",__FUNCTION__,patched_unidentified_number);
}

DWORD DiffMachine::DumpFunctionMatchInfo(int index,DWORD address)
{
	DWORD block_address=address;

	/*
	if(index==0)
		block_address=TheSource->GetBlockAddress(address);
	else
		block_address=TheTarget->GetBlockAddress(address);
	*/

	multimap <DWORD, MatchData>::iterator match_map_iter;
	if(index==0)
	{
		TheSource->DumpBlockInfo(block_address);
		match_map_iter=DiffResults->MatchMap.find(block_address);
		while(match_map_iter!=DiffResults->MatchMap.end() &&
			match_map_iter->first==block_address)
		{
			DumpMatchMapIterInfo("",match_map_iter);
			TheTarget->DumpBlockInfo(match_map_iter->second.Addresses[1]);
			match_map_iter++;
		}
	}
	else
	{
		TheTarget->DumpBlockInfo(block_address);
		hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator;
		reverse_match_map_iterator=DiffResults->ReverseAddressMap.find(block_address);
		if(reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end())
		{
			//DumpMatchMapIterInfo("",match_map_iter);
			//TheSource->DumpBlockInfo(match_map_iter->second.Addresses[1]);
			match_map_iter++;
		}
	}

	return 0L;
}

int ReadOneMatchMapCallback(void *arg,int argc,char **argv,char **names)
{
	MatchData *match_data=(MatchData *)arg;
	if(match_data)
	{
		match_data->Addresses[0]=strtoul10(argv[0]);
		match_data->Addresses[1]=strtoul10(argv[1]);
		match_data->Type=atoi(argv[3]);
		match_data->SubType=atoi(argv[4]);
		match_data->Status=atoi(argv[5]);
		match_data->MatchRate=atoi(argv[6]);
		match_data->UnpatchedParentAddress=strtoul10(argv[7]);
		match_data->PatchedParentAddress=strtoul10(argv[8]);
	}
	return 0;
}

MatchData *DiffMachine::GetMatchData(int index,DWORD address)
{
	DWORD block_address=address;
	

	if(!DiffResults && m_InputDB)
	{
		static MatchData match_data;
		memset(&match_data,0,sizeof(match_data));
		m_InputDB->ExecuteStatement(ReadOneMatchMapCallback,&match_data,"SELECT TheSourceAddress,TheTargetAddress,MatchType,Type,SubType,Status,MatchRate,UnpatchedParentAddress,PatchedParentAddress FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u",m_TheSourceFileID,m_TheTargetFileID,index==0?"TheSourceAddress":"TheTargetAddress",block_address);
		if(match_data.Addresses[0]!=0)
		{
			if(DebugLevel&1) dprintf("%s: %u 0x%x Returns %x-%x\r\n",__FUNCTION__,index,block_address,match_data.Addresses[0],match_data.Addresses[1]);
			return &match_data;
		}
	}else
	{
		if(index==1)
		{
			hash_map <DWORD,DWORD>::iterator reverse_match_map_iterator=DiffResults->ReverseAddressMap.find(block_address);
			if(reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end())
			{
				block_address=reverse_match_map_iterator->second;
			}else
			{
				block_address=0;
			}
		}
		
		if(block_address>0)
		{
			multimap <DWORD, MatchData>::iterator match_map_iter;
			match_map_iter=DiffResults->MatchMap.find(block_address);
			if(match_map_iter!=DiffResults->MatchMap.end())
			{
				if(DebugLevel&1) dprintf("%s: %u 0x%x Returns %x-%x\r\n",__FUNCTION__,index,block_address,match_map_iter->second.Addresses[0],match_map_iter->second.Addresses[1]);
				return &match_map_iter->second;
			}
		}
	}
	if(DebugLevel&1) dprintf("%s: %u 0x%x Returns NULL\r\n",__FUNCTION__,index,block_address);
	return NULL;
}

DWORD DiffMachine::GetMatchAddr(int index,DWORD address)
{
	MatchData *match_data=GetMatchData(index,address);
	if(match_data)
	{
		return match_data->Addresses[index==0?1:0];
	}
	return 0L;
}

enum {TYPE_MATCH,TYPE_REVERSE_MATCH,TYPE_BEFORE_UNIDENTIFIED_BLOCK,TYPE_AFTER_UNIDENTIFIED_BLOCK};
BOOL DiffMachine::Save(char *DataFile,BYTE Type,DWORD Offset,DWORD dwMoveMethod,hash_set <DWORD> *pTheSourceSelectedAddresses,hash_set <DWORD> *pTheTargetSelectedAddresses)
{
	if(Type==DiffMachineFileBinaryFormat)
	{
		int ret;
		ZlibWrapper *zlib_wrapper=new ZlibWrapper(TRUE,1);
		zlib_wrapper->SetOutFile(DataFile,Offset,dwMoveMethod);
		multimap <DWORD, MatchData>::iterator match_map_iter;
		for(match_map_iter=DiffResults->MatchMap.begin();
			match_map_iter!=DiffResults->MatchMap.end();
			match_map_iter++)
		{
			if(
				pTheSourceSelectedAddresses &&
				pTheSourceSelectedAddresses->find(match_map_iter->first)==
				pTheSourceSelectedAddresses->end()
			)
			{
				continue;
			}
			char type=TYPE_MATCH;
			ret=zlib_wrapper->WriteData((unsigned char *)&type,sizeof(type));
			if(!ret)
				return FALSE;
			ret=zlib_wrapper->WriteData((unsigned char *)
				&match_map_iter->first,
				sizeof(match_map_iter->first)
			);
			if(!ret)
				return FALSE;
			ret=zlib_wrapper->WriteData((unsigned char *)
				&match_map_iter->second,
				sizeof(match_map_iter->second)
			);
			if(!ret)
				return FALSE;
		}
		//Save Unidentified blocks
		hash_set <DWORD>::iterator unidentified_iter;
		for(unidentified_iter=TheSourceUnidentifedBlockHash.begin();unidentified_iter!=TheSourceUnidentifedBlockHash.end();unidentified_iter++)
		{
			if(
				pTheSourceSelectedAddresses &&
				pTheSourceSelectedAddresses->find(*unidentified_iter)==
				pTheSourceSelectedAddresses->end()
			)
			{
				continue;
			}
			BYTE type=TYPE_BEFORE_UNIDENTIFIED_BLOCK;
			ret=zlib_wrapper->WriteData((unsigned char *)
				&type,
				sizeof(type)
			);
			if(!ret)
				return FALSE;
			ret=zlib_wrapper->WriteData((unsigned char *)
				(PBYTE)&(*unidentified_iter),
				sizeof(DWORD)
			);
			if(!ret)
				return FALSE;
		}
		for(unidentified_iter=TheTargetUnidentifedBlockHash.begin();unidentified_iter!=TheTargetUnidentifedBlockHash.end();unidentified_iter++)
		{
			if(
				pTheTargetSelectedAddresses &&
				pTheTargetSelectedAddresses->find(*unidentified_iter)==
				pTheTargetSelectedAddresses->end()
			)
			{
				continue;
			}
			BYTE type=TYPE_AFTER_UNIDENTIFIED_BLOCK;
			ret=zlib_wrapper->WriteData((unsigned char *)
				&type,
				sizeof(type)
			);
			if(!ret)
				return FALSE;
			ret=zlib_wrapper->WriteData((unsigned char *)
				(PBYTE)&(*unidentified_iter),
				sizeof(DWORD)
			);
			if(!ret)
				return FALSE;
		}
		delete zlib_wrapper;
		return TRUE;
	}else if(Type==DiffMachineFileSQLiteFormat)
	{
	}
	return FALSE;
}

BOOL DiffMachine::Retrieve(char *DataFile,BYTE Type,DWORD Offset,DWORD Length)
{
	if(Type==DiffMachineFileBinaryFormat)
	{
		ZlibWrapper *zlib_wrapper=new ZlibWrapper(FALSE);
		if(!zlib_wrapper->SetInFile(DataFile,Offset,Length))
			return FALSE;

		DiffResults=new AnalysisResult;
		DiffResults->MatchMap.clear();
		DiffResults->ReverseAddressMap.clear();
		while(1)
		{
			char type;

			DWORD nBytesRead=zlib_wrapper->ReadData((unsigned char *)
				&type, 
				sizeof(type)) ; 
			if(nBytesRead!=sizeof(type))
				break;
			if(type==TYPE_MATCH || type==TYPE_REVERSE_MATCH)
			{
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *)
					&address, 
					sizeof(address)) ; 
				if(nBytesRead!=sizeof(address))
					break;
			
				MatchData match_data;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *)
					&match_data,
					sizeof(match_data)); 
				if(nBytesRead!=sizeof(match_data))
					break;
				if(type==TYPE_MATCH)
				{
					DiffResults->MatchMap.insert(MatchMap_Pair(address,match_data));
				}else
				{
					DiffResults->ReverseAddressMap.insert(pair<DWORD,DWORD>(address,match_data.Addresses[0]));
				}
			}else if(type==TYPE_BEFORE_UNIDENTIFIED_BLOCK || type==TYPE_AFTER_UNIDENTIFIED_BLOCK)
			{
				DWORD address;
				nBytesRead=zlib_wrapper->ReadData((unsigned char *)
					&address, 
					sizeof(address)) ; 
				if(nBytesRead!=sizeof(address))
					break;
				if(type==TYPE_BEFORE_UNIDENTIFIED_BLOCK)
				{
					TheSourceUnidentifedBlockHash.insert(address);
				}else
				{
					TheTargetUnidentifedBlockHash.insert(address);
				}
			}
		}
#ifdef REGNERATE_ANALYSIS_RESULT
		DiffResults->MatchMap.clear();
		DiffResults->ReverseAddressMap.clear();
		Analyze();
		RemoveDuplicates();
#endif
		GenerateFunctionMatchInfo();
		delete zlib_wrapper;
		return TRUE;
	}else if(Type==DiffMachineFileSQLiteFormat)
	{
	}
	return FALSE;
}

BOOL DiffMachine::Save(DBWrapper& OutputDB,hash_set <DWORD> *pTheSourceSelectedAddresses,hash_set <DWORD> *pTheTargetSelectedAddresses)
{
	if(!TheSource || !TheTarget)
		return FALSE;

	OutputDB.ExecuteStatement(NULL,NULL,DELETE_MATCH_MAP_TABLE_STATEMENT,
		TheSource->GetFileID(),
		TheTarget->GetFileID());
	OutputDB.ExecuteStatement(NULL,NULL,CREATE_MATCH_MAP_TABLE_STATEMENT);
	OutputDB.ExecuteStatement(NULL,NULL,CREATE_MATCH_MAP_TABLE_INDEX_STATEMENT);		

	OutputDB.ExecuteStatement(NULL,NULL,DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT,
		TheSource->GetFileID(),
		TheTarget->GetFileID());		
	OutputDB.ExecuteStatement(NULL,NULL,CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT);
	OutputDB.ExecuteStatement(NULL,NULL,CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT);

	OutputDB.BeginTransaction();
	multimap <DWORD, MatchData>::iterator match_map_iter;
	if(DebugLevel&1) dprintf("DiffResults->MatchMap.size()=%u\n",DiffResults->MatchMap.size());
	for(match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++)
	{
		if(
			pTheSourceSelectedAddresses &&
			pTheSourceSelectedAddresses->find(match_map_iter->first)==
			pTheSourceSelectedAddresses->end()
		)
		{
			continue;
		}
		//INSERT
		//match_map_iter->first
		//match_map_iter->second
		OutputDB.ExecuteStatement(NULL,NULL,INSERT_MATCH_MAP_TABLE_STATEMENT,
			TheSource->GetFileID(),
			TheTarget->GetFileID(),
			match_map_iter->first,
			match_map_iter->second.Addresses[1],
			TYPE_MATCH,
			match_map_iter->second.Type,
			match_map_iter->second.SubType,
			match_map_iter->second.Status,
			match_map_iter->second.MatchRate,
			match_map_iter->second.UnpatchedParentAddress,
			match_map_iter->second.PatchedParentAddress);
	}

	if(DebugLevel&1) dprintf("FunctionMatchInfoList.size()=%u\n",FunctionMatchInfoList.size());
	vector <FunctionMatchInfo>::iterator iter;
	for(iter=FunctionMatchInfoList.begin();iter!=FunctionMatchInfoList.end();iter++)
	{
		//*iter
		//if(iter->BlockType==FUNCTION_BLOCK)
		{
			if(DebugLevel&1) dprintf(INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT"\r\n",
				TheSource->GetFileID(),
				TheTarget->GetFileID(),
				iter->TheSourceAddress,
				iter->EndAddress,
				iter->TheTargetAddress,
				iter->BlockType,
				iter->MatchRate,
				iter->TheSourceFunctionName,
				iter->Type,
				iter->TheTargetFunctionName,
				iter->MatchCountForTheSource,
				iter->NoneMatchCountForTheSource,
				iter->MatchCountWithModificationForTheSource,
				iter->MatchCountForTheTarget,
				iter->NoneMatchCountForTheTarget,
				iter->MatchCountWithModificationForTheTarget
				);

			OutputDB.ExecuteStatement(NULL,NULL,INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT,
				TheSource->GetFileID(),
				TheTarget->GetFileID(),
				iter->TheSourceAddress,
				iter->EndAddress,
				iter->TheTargetAddress,
				iter->BlockType,
				iter->MatchRate,
				iter->TheSourceFunctionName,
				iter->Type,
				iter->TheTargetFunctionName,
				iter->MatchCountForTheSource,
				iter->NoneMatchCountForTheSource,
				iter->MatchCountWithModificationForTheSource,
				iter->MatchCountForTheTarget,
				iter->NoneMatchCountForTheTarget,
				iter->MatchCountWithModificationForTheTarget
				);
		}
	}
#ifdef SAVE_UNINDENTIFIED_BLOCKS_TO_DB
	OutputDB.ExecuteStatement(NULL,NULL,CREATE_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT);
	
	//Save Unidentified blocks
	hash_set <DWORD>::iterator unidentified_iter;
	for(unidentified_iter=TheSourceUnidentifedBlockHash.begin();unidentified_iter!=TheSourceUnidentifedBlockHash.end();unidentified_iter++)
	{
		if(
			pTheSourceSelectedAddresses &&
			pTheSourceSelectedAddresses->find(*unidentified_iter)==
			pTheSourceSelectedAddresses->end()
		)
		{
			continue;
		}
		//INSERT
		OutputDB.ExecuteStatement(NULL,NULL,INSERT_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT,
			TYPE_BEFORE_UNIDENTIFIED_BLOCK,
			*unidentified_iter
			);

	}
	for(unidentified_iter=TheTargetUnidentifedBlockHash.begin();unidentified_iter!=TheTargetUnidentifedBlockHash.end();unidentified_iter++)
	{
		if(
			pTheTargetSelectedAddresses &&
			pTheTargetSelectedAddresses->find(*unidentified_iter)==
			pTheTargetSelectedAddresses->end()
		)
		{
			continue;
		}
		//INSERT
		OutputDB.ExecuteStatement(NULL,NULL,INSERT_UNIDENTIFIED_BLOCKS_TABLE_STATEMENT,
			TYPE_AFTER_UNIDENTIFIED_BLOCK,
			*unidentified_iter
			);
	}
#endif
	OutputDB.EndTransaction();
	return TRUE;
}

int ReadMatchMapCallback(void *arg,int argc,char **argv,char **names)
{
	//if(DebugLevel&1) dprintf("%s: %s %s %s %s\n",__FUNCTION__,argv[0],argv[1],argv[2],argv[3]);
	AnalysisResult *DiffResults=(AnalysisResult *)arg;

	MatchData match_data;
	DWORD TheSourceAddress=strtoul10(argv[0]);
	DWORD TheTargetAddress=strtoul10(argv[1]);
	match_data.Type=atoi(argv[3]);
	match_data.SubType=atoi(argv[4]);
	match_data.Status=atoi(argv[5]);
	match_data.MatchRate=atoi(argv[6]);
	match_data.UnpatchedParentAddress=strtoul10(argv[7]);
	match_data.PatchedParentAddress=strtoul10(argv[8]);

	match_data.Addresses[0]=TheSourceAddress;
	match_data.Addresses[1]=TheTargetAddress;
	DiffResults->MatchMap.insert(MatchMap_Pair(TheSourceAddress,match_data));
	DiffResults->ReverseAddressMap.insert(pair<DWORD,DWORD>(TheTargetAddress,TheSourceAddress));
	return 0;
}

int ReadFunctionMatchInfoListCallback(void *arg,int argc,char **argv,char **names)
{
	vector <FunctionMatchInfo> *pFunctionMatchInfoList=(vector <FunctionMatchInfo> *)arg;
	FunctionMatchInfo function_match_info;
	function_match_info.TheSourceAddress=strtoul10(argv[0]);
	function_match_info.EndAddress=strtoul10(argv[1]);
	function_match_info.TheTargetAddress=strtoul10(argv[2]);
	function_match_info.BlockType=atoi(argv[3]);
	function_match_info.MatchRate=atoi(argv[4]);
	function_match_info.TheSourceFunctionName=_strdup(argv[5]);
	function_match_info.Type=atoi(argv[6]);
	function_match_info.TheTargetFunctionName=_strdup(argv[7]);
	function_match_info.MatchCountForTheSource=atoi(argv[8]);
	function_match_info.NoneMatchCountForTheSource=atoi(argv[9]);
	function_match_info.MatchCountWithModificationForTheSource=atoi(argv[10]);
	function_match_info.MatchCountForTheTarget=atoi(argv[11]);
	function_match_info.NoneMatchCountForTheTarget=atoi(argv[12]);
	function_match_info.MatchCountWithModificationForTheTarget=atoi(argv[13]);
	pFunctionMatchInfoList->push_back(function_match_info);
	return 0;
}

BOOL DiffMachine::Retrieve(DBWrapper& InputDB,BOOL bRetrieveDataForAnalysis,int TheSourceFileID,int TheTargetFileID,BOOL bLoadMatchMapToMemory)
{
	TheSource=new OneIDAClientManager();
	TheTarget=new OneIDAClientManager();
	TheSource->Retrieve(&InputDB,TheSourceFileID,bRetrieveDataForAnalysis);
	TheTarget->Retrieve(&InputDB,TheTargetFileID,bRetrieveDataForAnalysis);
	m_InputDB=&InputDB;
	m_TheSourceFileID=TheSourceFileID;
	m_TheTargetFileID=TheTargetFileID;
	InputDB.ExecuteStatement(ReadFunctionMatchInfoListCallback,&FunctionMatchInfoList,"SELECT TheSourceAddress,EndAddress,TheTargetAddress,BlockType,MatchRate,TheSourceFunctionName,Type,TheTargetFunctionName,MatchCountForTheSource,NoneMatchCountForTheSource,MatchCountWithModificationForTheSource,MatchCountForTheTarget,NoneMatchCountForTheTarget,MatchCountWithModificationForTheTarget From " FUNCTION_MATCH_INFO_TABLE" WHERE TheSourceFileID=%u AND TheTargetFileID=%u",TheSourceFileID,TheTargetFileID);
	if(bLoadMatchMapToMemory)
	{
		DiffResults=new AnalysisResult;
		InputDB.ExecuteStatement(ReadMatchMapCallback,DiffResults,"SELECT TheSourceAddress,TheTargetAddress,MatchType,Type,SubType,Status,MatchRate,UnpatchedParentAddress,PatchedParentAddress From MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u",TheSourceFileID,TheTargetFileID);
	}else
	{
		if(DiffResults)
			delete DiffResults;
		DiffResults=NULL;
	}
	return TRUE;
}

char *DiffMachine::GetMatchTypeStr(int Type)
{
	static char *TypeStr[]={"Name","Fingerprint","Two Level Fingerprint","Tree","Fingerprint Inside Function","Function"};
	if(Type<sizeof(TypeStr)/sizeof(TypeStr[0]))
	{
		return TypeStr[Type];
	}
	return "Unknown";
}
		