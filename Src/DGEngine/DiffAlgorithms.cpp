#include <string>
#include <list>
#include <unordered_set>
#include <unordered_map>
#include <stdlib.h>
#include <tchar.h>
#include <malloc.h>

#include "Diff.h"
#include "DiffAlgorithms.h"
#include "Log.h"
#include "LogOperation.h"
#include "Configuration.h"

extern LogOperation Logger;

using namespace std;
using namespace stdext;

DiffAlgorithms::DiffAlgorithms()
{
}

DiffAlgorithms::~DiffAlgorithms()
{
}

int DiffAlgorithms::GetInstructionHashMatchRate(unsigned char *unpatched_finger_print, unsigned char *patched_finger_print)
{
	int rate = 0;
	char *unpatched_finger_print_str = BytesWithLengthAmbleToHex(unpatched_finger_print);
	if (unpatched_finger_print_str)
	{
		char *patched_finger_print_str = BytesWithLengthAmbleToHex(patched_finger_print);
		if (patched_finger_print_str)
		{
			int unpatched_finger_print_str_len = strlen(unpatched_finger_print_str);
			int patched_finger_print_str_len = strlen(patched_finger_print_str);
			int diff_len = (unpatched_finger_print_str_len - patched_finger_print_str_len);
			if (diff_len > unpatched_finger_print_str_len  *0.5 || diff_len > patched_finger_print_str_len  *0.5)
			{
				rate = 0;
			}
			else
			{
				rate = GetStringSimilarity(unpatched_finger_print_str, patched_finger_print_str);
			}
			free(unpatched_finger_print_str);
		}
		free(patched_finger_print_str);
	}
	return rate;
}

void DiffAlgorithms::RemoveDuplicates(MATCHMAP *pMatchMap)
{
	multimap <va_t, MatchData>::iterator match_map_iter;
	multimap <va_t, MatchData>::iterator found_match_map_iter;
	multimap <va_t, MatchData>::iterator max_match_map_iter;
	for (match_map_iter = pMatchMap->begin();
		match_map_iter != pMatchMap->end();
		match_map_iter++)
	{
		if (match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
			continue;
		int found_duplicate = FALSE;
		max_match_map_iter = match_map_iter;
		int maximum_matchrate = match_map_iter->second.MatchRate;
		for (found_match_map_iter = pMatchMap->find(match_map_iter->first);
			found_match_map_iter != pMatchMap->end() && match_map_iter->first == found_match_map_iter->first;
			found_match_map_iter++)
		{
			if (!(found_match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
				&& match_map_iter->second.Addresses[1] != found_match_map_iter->second.Addresses[1])
			{
				//Duplicates found
				if (maximum_matchrate <= found_match_map_iter->second.MatchRate)
				{
					found_duplicate = TRUE;
					max_match_map_iter = found_match_map_iter;
					maximum_matchrate = found_match_map_iter->second.MatchRate;
				}
			}
		}
		/*
		if( found_duplicate )
		{
			if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Choosing %X %X match\n", , max_match_map_iter->first, max_match_map_iter->second.Addresses[1] );
			DumpMatchMapIterInfo( __FUNCTION__, max_match_map_iter );
			for ( found_match_map_iter=DiffResults->MatchMap.find( match_map_iter->first );
				found_match_map_iter!=DiffResults->MatchMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++ )
			{
				if( max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
				{
					if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Removing %X %X match\n", found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );
					DumpMatchMapIterInfo( __FUNCTION__, found_match_map_iter );
					found_match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
					RevokeTreeMatchMapIterInfo( found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );

					unordered_map <va_t, va_t>::iterator reverse_match_map_iterator=DiffResults->ReverseAddressMap.find( found_match_map_iter->second.Addresses[1] );
					if( reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end() && reverse_match_map_iterator->second.Address==found_match_map_iter->first )
					{
						iter->second.Status|=STATUS_MAPPING_DISABLED;
						RevokeTreeMatchMapIterInfo( iter->first, iter->second.Address );
					}
				}
			}
		}*/
	}

	/*CLEAN UP
	unordered_map <va_t, va_t>::iterator reverse_match_map_iterator;
	for ( reverse_match_map_iterator=DiffResults->ReverseAddressMap.begin();
		reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end();
		reverse_match_map_iterator++ )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
			continue;
		int found_duplicate=FALSE;
		max_match_map_iter=match_map_iter;
		int maximum_matchrate=match_map_iter->second.MatchRate;
		unordered_map <va_t, va_t>::iterator found_reverse_match_map_iterator;
		for ( found_match_map_iter=DiffResults->ReverseAddressMap.find( match_map_iter->first );
			found_match_map_iter!=DiffResults->ReverseAddressMap.end() &&
			match_map_iter->first==found_match_map_iter->first;
			found_match_map_iter++ )
		{
			if( !( found_match_map_iter->second.Status&STATUS_MAPPING_DISABLED ) &&
				match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
			{
				//Duplicates found
				if( maximum_matchrate<found_match_map_iter->second.MatchRate )
				{
					found_duplicate=TRUE;
					max_match_map_iter=found_match_map_iter;
					maximum_matchrate=found_match_map_iter->second.MatchRate;
				}
			}
		}
		if( found_duplicate )
		{
			if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Choosing( reverse ) %X %X match\n", __FUNCTION__, max_match_map_iter->first, max_match_map_iter->second.Addresses[1] );
			DumpMatchMapIterInfo( __FUNCTION__, max_match_map_iter );
			unordered_map <va_t, va_t>::iterator reverse_match_map_iterator;
			for ( found_match_map_iter=DiffResults->ReverseAddressMap.find( match_map_iter->first );
				found_match_map_iter!=DiffResults->ReverseAddressMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++ )
			{
				if( max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
				{
					if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Removing( reverse ) %X:%X match\n", __FUNCTION__,
							found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );
					DumpMatchMapIterInfo( __FUNCTION__, found_match_map_iter );
					found_match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
					RevokeTreeMatchMapIterInfo( found_match_map_iter->second.Addresses[1], found_match_map_iter->first );
					multimap <va_t,  MatchData>::iterator iter=DiffResults->MatchMap.find( found_match_map_iter->second.Addresses[1] );
					for ( ;iter!=DiffResults->MatchMap.end() && iter->first==found_match_map_iter->second.Addresses[1];iter++ )
					{
						if( iter->second.Address==found_match_map_iter->first )
						{
							iter->second.Status|=STATUS_MAPPING_DISABLED;
							RevokeTreeMatchMapIterInfo( iter->second.Address, iter->first );
						}
					}
				}
			}
		}
	}
	*/
}

void DiffAlgorithms::RevokeTreeMatchMapIterInfo(MATCHMAP *pMatchMap, va_t address, va_t match_address)
{
	return;
	multimap <va_t, MatchData>::iterator match_map_iter;
	for (match_map_iter = pMatchMap->begin();
		match_map_iter != pMatchMap->end();
		match_map_iter++)
	{
		if (match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
			continue;
		if (match_map_iter->second.Type == TREE_MATCH)
		{
			if (match_map_iter->second.UnpatchedParentAddress == address && match_map_iter->second.PatchedParentAddress == match_address)
			{
				match_map_iter->second.Status |= STATUS_MAPPING_DISABLED;
				RevokeTreeMatchMapIterInfo(pMatchMap, match_map_iter->first, match_map_iter->second.Addresses[1]);
			}
		}
	}
}

FunctionMatchInfoList *DiffAlgorithms::GenerateFunctionMatchInfo(MATCHMAP *pMatchMap, multimap <va_t, va_t> *pReverseAddressMap)
{
    FunctionMatchInfoList *pFunctionMatchInfoList = new FunctionMatchInfoList();
	multimap <va_t, MatchData>::iterator match_map_iter;
	va_t last_unpatched_addr = 0;
	va_t last_patched_addr = 0;
	FunctionMatchInfo match_info;

	for (match_map_iter = pMatchMap->begin(); match_map_iter != pMatchMap->end(); match_map_iter++)
	{
		if (match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
		{
			LogMessage(0, __FUNCTION__, "Skipping %X %X\n", match_map_iter->first, match_map_iter->second.Addresses[1]);
			continue;
		}
		PBasicBlock p_basic_block = SourceLoader->GetBasicBlock(match_map_iter->first);

		if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(match_map_iter->first, 0))
		{
			Logger.Log(11, LOG_DIFF_MACHINE, "%X Block Type: %d\n", match_map_iter->first,
				p_basic_block ? p_basic_block->BlockType : -1);
		}

		if (p_basic_block && p_basic_block->BlockType == FUNCTION_BLOCK)
		{
			match_info.SourceAddress = match_map_iter->first;
			match_info.BlockType = p_basic_block->BlockType;
			match_info.EndAddress = p_basic_block->EndAddress;
			match_info.Type = match_map_iter->second.Type;
			match_info.TargetAddress = match_map_iter->second.Addresses[1];
			match_info.MatchRate = 99;

			if (last_unpatched_addr != match_info.SourceAddress &&
				last_patched_addr != match_info.TargetAddress
				)
			{
				match_info.SourceFunctionName = SourceLoader->GetSymbol(match_info.SourceAddress);
				match_info.TargetFunctionName = TargetLoader->GetSymbol(match_info.TargetAddress);

				float source_match_rate = 0.0;

                /*TODO:
				GetMatchStatistics(
					match_info.SourceAddress,
					0,
					match_info.MatchCountForTheSource,
					match_info.MatchCountWithModificationForTheSource,
					match_info.NoneMatchCountForTheSource,
					source_match_rate
				);*/

				float target_match_rate = 0;
                /*TODO:
				GetMatchStatistics(
					match_info.TargetAddress,
					1,
					match_info.MatchCountForTheTarget,
					match_info.MatchCountWithModificationForTheTarget,
					match_info.NoneMatchCountForTheTarget,
					target_match_rate
				);*/

				float match_rate = (source_match_rate + target_match_rate) / 2;
				match_info.MatchRate = match_rate;

				if (match_rate != 100 && match_info.MatchRate == 100)
				{
					match_info.MatchRate = 99;
				}

				pFunctionMatchInfoList->Add(match_info);
			}
			last_unpatched_addr = match_info.SourceAddress;
			last_patched_addr = match_info.TargetAddress;
		}
	}

	LogMessage(0, __FUNCTION__, "pFunctionMatchInfoList->Size()=%u\n", pFunctionMatchInfoList->Size());

	int unpatched_unidentified_number = 0;
	for (auto& val : SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map)
	{
		if (pMatchMap->find(val.first) == pMatchMap->end())
		{
			PBasicBlock p_basic_block = SourceLoader->GetBasicBlock(val.first);
			if (p_basic_block)
			{
				if (p_basic_block->BlockType == FUNCTION_BLOCK)
				{
					match_info.SourceAddress = p_basic_block->StartAddress;
					match_info.SourceFunctionName = SourceLoader->GetSymbol(match_info.SourceAddress);
					match_info.BlockType = p_basic_block->BlockType;
					match_info.EndAddress = p_basic_block->EndAddress;
					match_info.Type = 0;
					match_info.TargetAddress = 0;
					match_info.TargetFunctionName = _strdup("");
					match_info.MatchRate = 0;
					match_info.MatchCountForTheSource = 0;
					match_info.MatchCountWithModificationForTheSource = 0;
					match_info.NoneMatchCountForTheSource = 0;

					match_info.MatchCountForTheTarget = 0;
					match_info.MatchCountWithModificationForTheTarget = 0;
					match_info.NoneMatchCountForTheTarget = 0;

					pFunctionMatchInfoList->Add(match_info);
				}
				//TODO: m_sourceUnidentifedBlockHash.insert(p_basic_block->StartAddress);
			}
			unpatched_unidentified_number++;
		}
	}

	//TODO: LogMessage(0, __FUNCTION__, "unpatched_unidentified_number=%u\n", m_sourceUnidentifedBlockHash.size());

	int patched_unidentified_number = 0;
	for (auto& val : TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map)
	{
		if (pReverseAddressMap->find(val.first) == pReverseAddressMap->end())
		{
			PBasicBlock p_basic_block = TargetLoader->GetBasicBlock(val.first);
			if (p_basic_block)
			{
				if (p_basic_block->BlockType == FUNCTION_BLOCK)
				{
					match_info.SourceAddress = 0;
					match_info.SourceFunctionName = _strdup("");
					match_info.BlockType = p_basic_block->BlockType;
					match_info.EndAddress = 0;
					match_info.Type = 0;
					match_info.TargetAddress = p_basic_block->StartAddress;
					match_info.TargetFunctionName = TargetLoader->GetSymbol(match_info.TargetAddress);
					match_info.MatchRate = 0;
					match_info.MatchCountForTheSource = 0;
					match_info.MatchCountWithModificationForTheSource = 0;
					match_info.NoneMatchCountForTheSource = 0;

					match_info.MatchCountForTheTarget = 0;
					match_info.MatchCountWithModificationForTheTarget = 0;
					match_info.NoneMatchCountForTheTarget = 0;

					pFunctionMatchInfoList->Add(match_info);
				}

				//TODO: m_targetUnidentifedBlockHash.insert(p_basic_block->StartAddress);
				free(p_basic_block);
			}

			patched_unidentified_number++;
		}
	}

	//TODO: LogMessage(0, __FUNCTION__, "patched_unidentified_number=%u\n", patched_unidentified_number);

	return pFunctionMatchInfoList;
}

/*REMOVE:
BOOL DiffAlgorithms::DeleteMatchInfo(DiffStorage & diffStorage)
{
	if (SourceFunctionAddress > 0 && targetFunctionAddress > 0)
	{
		SourceLoader->DeleteMatchInfo(&diffStorage, SourceLoader->GetFileID(), SourceFunctionAddress);
		TargetLoader->DeleteMatchInfo(&diffStorage, TargetLoader->GetFileID(), targetFunctionAddress);
	}
	else
	{
		diffStorage.DeleteMatches(SourceLoader->GetFileID(), TargetLoader->GetFileID());
	}
	return TRUE;
}*/

void DiffAlgorithms::PurgeInstructionHashHashMap(MATCHMAP *pTemporaryMap)
{
	multimap <va_t, MatchData>::iterator match_map_iter;

	for (match_map_iter = pTemporaryMap->begin();
		match_map_iter != pTemporaryMap->end();
		match_map_iter++)
	{
		//Remove from instruction_hash hash map
		multimap <va_t, unsigned char*>::iterator address_to_instruction_hash_map_Iter;
		address_to_instruction_hash_map_Iter = SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(match_map_iter->second.Addresses[0]);
		if (address_to_instruction_hash_map_Iter != SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
		{
			SourceLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.erase(address_to_instruction_hash_map_Iter->second);
		}
		address_to_instruction_hash_map_Iter = TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(match_map_iter->second.Addresses[1]);
		if (address_to_instruction_hash_map_Iter != TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
		{
			TargetLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.erase(address_to_instruction_hash_map_Iter->second);
		}
	}

	LogMessage(0, __FUNCTION__, "%u-%u\n",
		SourceLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.size(),
		TargetLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.size());
}

MATCHMAP *DiffAlgorithms::DoInstructionHashMatchInsideFunction(va_t SourceFunctionAddress, list <va_t>& SourceBlockAddresses, va_t targetFunctionAddress, list <va_t>& TargetBlockAddresses)
{
    MATCHMAP *pMatchMap = new MATCHMAP;

	//InstructionHash match on SourceBlockAddresses, TargetBlockAddresse
	/*
	list <va_t>::iterator SourceBlockAddressIter;
	for ( SourceBlockAddressIter=SourceBlockAddresses.begin();SourceBlockAddressIter!=SourceBlockAddresses.end();SourceBlockAddressIter++ )
	{
		va_t SourceAddress=*SourceBlockAddressIter;
		multimap <va_t, MatchData>:: MatchDataIterator;
		MatchDataIterator=pTemporaryMap->find( SourceAddress );
		if( MatchDataIterator!=pTemporaryMap->end() )
		{
			va_t TargetAddress=MatchDataIterator->second.Addresses[1];
			TargetBlockAddresse.erase( TargetAddress );
		}
	}*/
	//Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Entry\n");
	multimap <va_t, unsigned char*>::iterator address_to_instruction_hash_map_Iter;
	unordered_map <unsigned char*, AddressesInfo, hash_compare_instruction_hash> instruction_hash_map;
	unordered_map <unsigned char*, AddressesInfo, hash_compare_instruction_hash>::iterator instruction_hash_map_iter;

	for (va_t SourceAddress : SourceBlockAddresses)
	{
		//Logger.Log( 10, LOG_DIFF_MACHINE,  "\tSource=%X\n", SourceAddress );
		address_to_instruction_hash_map_Iter = SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(SourceAddress);
		if (address_to_instruction_hash_map_Iter != SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
		{
			unsigned char *InstructionHash = address_to_instruction_hash_map_Iter->second;
			instruction_hash_map_iter = instruction_hash_map.find(InstructionHash);
			if (instruction_hash_map_iter != instruction_hash_map.end())
			{
				instruction_hash_map_iter->second.Overflowed = TRUE;
			}
			else
			{
				AddressesInfo OneAddressesInfo;
				OneAddressesInfo.Overflowed = FALSE;
				OneAddressesInfo.SourceAddress = SourceAddress;
				OneAddressesInfo.TargetAddress = 0L;
				instruction_hash_map.insert(pair<unsigned char*, AddressesInfo>(InstructionHash, OneAddressesInfo));
			}
		}
	}

	for (va_t targetAddress: TargetBlockAddresses)
	{
		//Logger.Log( 10, LOG_DIFF_MACHINE,  "\tTarget=%X\n", TargetAddress );
		address_to_instruction_hash_map_Iter = TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(targetAddress);
		if (address_to_instruction_hash_map_Iter != TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
		{
			unsigned char *InstructionHash = address_to_instruction_hash_map_Iter->second;
			instruction_hash_map_iter = instruction_hash_map.find(InstructionHash);
			if (instruction_hash_map_iter != instruction_hash_map.end())
			{
				if (instruction_hash_map_iter->second.TargetAddress != 0L)
					instruction_hash_map_iter->second.Overflowed = TRUE;
				else
					instruction_hash_map_iter->second.TargetAddress = targetAddress;
			}
			else
			{
				AddressesInfo OneAddressesInfo;
				OneAddressesInfo.Overflowed = FALSE;
				OneAddressesInfo.SourceAddress = 0L;
				OneAddressesInfo.TargetAddress = targetAddress;
				instruction_hash_map.insert(pair<unsigned char*, AddressesInfo>(InstructionHash, OneAddressesInfo));
			}
		}
	}

	for (auto& val : instruction_hash_map)
	{
		if (!val.second.Overflowed &&
			val.second.SourceAddress != 0L &&
			val.second.TargetAddress != 0L)
		{
			//Logger.Log( 10, LOG_DIFF_MACHINE,  "%X %X\n", val.second.SourceAddress, val.second.TargetAddress );
			//We found matching blocks
			//val.second.SourceAddress, val.second.TargetAddress
			MatchData match_data;
			memset(&match_data, 0, sizeof(MatchData));
			match_data.Type = INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH;
			match_data.Addresses[0] = val.second.SourceAddress;
			match_data.Addresses[1] = val.second.TargetAddress;

			match_data.UnpatchedParentAddress = SourceFunctionAddress;
			match_data.PatchedParentAddress = targetFunctionAddress;
			match_data.MatchRate = 100;

			if (m_pdumpAddressChecker)
				m_pdumpAddressChecker->DumpMatchInfo(match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate, "%s Add instruction_hash match:\n", __FUNCTION__);
            pMatchMap->insert(MatchMap_Pair(match_data.Addresses[0], match_data));
		}
	}
	instruction_hash_map.clear();

    return pMatchMap;
}

MATCHMAP *DiffAlgorithms::DoInstructionHashMatch()
{
    MATCHMAP *p_match_map = new MATCHMAP;
	multimap <unsigned char*, va_t, hash_compare_instruction_hash>::iterator instruction_hash_map_pIter;
	multimap <unsigned char*, va_t, hash_compare_instruction_hash>::iterator patched_instruction_hash_map_pIter;

	for (auto& val : SourceLoader->GetClientDisassemblyHashMaps()->instruction_hash_map)
	{
		if (SourceLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.count(val.first) == 1)
		{
			//unique key
			if (TargetLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.count(val.first) == 1)
			{
				patched_instruction_hash_map_pIter = TargetLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.find(val.first);
				if (patched_instruction_hash_map_pIter != TargetLoader->GetClientDisassemblyHashMaps()->instruction_hash_map.end())
				{
					MatchData match_data;
					memset(&match_data, 0, sizeof(MatchData));
					match_data.Type = INSTRUCTION_HASH_MATCH;
					match_data.Addresses[0] = instruction_hash_map_pIter->second;
					match_data.Addresses[1] = patched_instruction_hash_map_pIter->second;
					match_data.MatchRate = 100;

					if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
						LogMessage(0, __FUNCTION__, "%X-%X: %d%%\n", match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

					p_match_map->insert(MatchMap_Pair(match_data.Addresses[0], match_data));
				}
			}
		}
	}

	LogMessage(0, __FUNCTION__, "Matched pair count=%u\n", p_match_map->size());

    return p_match_map;
}

MatchRateInfo *DiffAlgorithms::GetMatchRateInfoArray(va_t source_address, va_t target_address, int type, int& match_rate_info_count)
{
	int source_addresses_number;
	int target_addresses_number;
	match_rate_info_count = 0;
	bool debug = false;

	if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(source_address, target_address))
	{
		debug = true;
		LogMessage(0, __FUNCTION__, "%X-%X %d\n", source_address, target_address, type);
	}

	va_t *source_addresses = SourceLoader->GetMappedAddresses(source_address, type, &source_addresses_number);
	va_t *target_addresses = TargetLoader->GetMappedAddresses(target_address, type, &target_addresses_number);

	if (debug)
	{
		LogMessage(0, __FUNCTION__, "Tree Matching Mapped Address Count: %X( %X ) %X( %X )\n",
			source_addresses_number, source_address,
			target_addresses_number, target_address);

		int i;
		LogMessage(0, __FUNCTION__, "Source Addresses:\n");
		for (i = 0; i < source_addresses_number; i++)
			LogMessage(0, __FUNCTION__, "\t%X\n", source_addresses[i]);


		LogMessage(0, __FUNCTION__, "Target Addresses:\n");
		for (i = 0; i < target_addresses_number; i++)
			LogMessage(0, __FUNCTION__, "\t%X\n", target_addresses[i]);
	}

	if (source_addresses_number != 0 && target_addresses_number != 0)
	{
		MatchRateInfo *p_match_rate_info_array = new MatchRateInfo[source_addresses_number  *target_addresses_number];

		if (source_addresses_number > 2 && source_addresses_number == target_addresses_number && type == CREF_FROM)
		{
			//Special case for switch case
			for (int i = 0; i < source_addresses_number; i++)
			{
				multimap <va_t, unsigned char*>::iterator source_instruction_hash_map_Iter = SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(source_addresses[i]);
				multimap <va_t, unsigned char*>::iterator target_instruction_hash_map_Iter = TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(target_addresses[i]);

				if (source_instruction_hash_map_Iter != SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end() &&
					target_instruction_hash_map_Iter != TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
				{
					p_match_rate_info_array[match_rate_info_count].Source = source_addresses[i];
					p_match_rate_info_array[match_rate_info_count].Target = target_addresses[i];

					p_match_rate_info_array[match_rate_info_count].MatchRate = GetInstructionHashMatchRate
					(source_instruction_hash_map_Iter->second,
						target_instruction_hash_map_Iter->second);
					p_match_rate_info_array[match_rate_info_count].IndexDiff = 0;
					if (debug)
						LogMessage(0, __FUNCTION__, "\tAdding %X-%X (%d%%, IndexDiff:%d)\n", p_match_rate_info_array[match_rate_info_count].Source, p_match_rate_info_array[match_rate_info_count].Target, p_match_rate_info_array[match_rate_info_count].MatchRate, p_match_rate_info_array[match_rate_info_count].IndexDiff);
					match_rate_info_count++;
				}
			}
		}
		else
		{
			if (debug)
				LogMessage(0, __FUNCTION__, "Adding matches\n");

			multimap <va_t, va_t> address_pair_map;
			for (int i = 0; i < source_addresses_number; i++)
			{
				multimap <va_t, unsigned char*>::iterator source_instruction_hash_map_Iter = SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(source_addresses[i]);

				for (int j = 0; j < target_addresses_number; j++)
				{
					multimap <va_t, va_t>::iterator it = address_pair_map.find(source_addresses[i]);

					bool skip = false;
					if (it != address_pair_map.end())
					{
						for (; it != address_pair_map.end() && it->first == source_addresses[i]; it++)
						{
							if (it->second == target_addresses[j])
							{
								skip = true;
								break;
							}
						}
					}

					if (skip)
						continue;

					address_pair_map.insert(pair<va_t, va_t>(source_addresses[i], target_addresses[j]));

					multimap <va_t, unsigned char*>::iterator target_instruction_hash_map_Iter = TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.find(target_addresses[j]);

					if (source_instruction_hash_map_Iter != SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end() &&
						target_instruction_hash_map_Iter != TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
					{
						p_match_rate_info_array[match_rate_info_count].Source = source_addresses[i];
						p_match_rate_info_array[match_rate_info_count].Target = target_addresses[j];

						p_match_rate_info_array[match_rate_info_count].MatchRate = GetInstructionHashMatchRate(source_instruction_hash_map_Iter->second, target_instruction_hash_map_Iter->second);
						p_match_rate_info_array[match_rate_info_count].IndexDiff = abs(i - j);
						if (debug)
							LogMessage(0, __FUNCTION__, "\tAdding %X-%X (%d%%, IndexDiff: %d)\n", p_match_rate_info_array[match_rate_info_count].Source, p_match_rate_info_array[match_rate_info_count].Target, p_match_rate_info_array[match_rate_info_count].MatchRate, p_match_rate_info_array[match_rate_info_count].IndexDiff);
						match_rate_info_count++;
					}
					else if (source_instruction_hash_map_Iter == SourceLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end() &&
						target_instruction_hash_map_Iter == TargetLoader->GetClientDisassemblyHashMaps()->address_to_instruction_hash_map.end())
					{
						p_match_rate_info_array[match_rate_info_count].Source = source_addresses[i];
						p_match_rate_info_array[match_rate_info_count].Target = target_addresses[j];
						p_match_rate_info_array[match_rate_info_count].MatchRate = 100;
						p_match_rate_info_array[match_rate_info_count].IndexDiff = abs(i - j);
						if (debug)
							LogMessage(0, __FUNCTION__, "\tAdding %X-%X (%d%%, IndexDiff: %d)\n", p_match_rate_info_array[match_rate_info_count].Source, p_match_rate_info_array[match_rate_info_count].Target, p_match_rate_info_array[match_rate_info_count].MatchRate, p_match_rate_info_array[match_rate_info_count].IndexDiff);
						match_rate_info_count++;
					}
				}
			}

			if (source_addresses)
				free(source_addresses);

			if (target_addresses)
				free(target_addresses);

			return p_match_rate_info_array;
		}
	}

	return NULL;
}

MATCHMAP *DiffAlgorithms::DoIsomorphMatch(MATCHMAP *pMainMatchMap, MATCHMAP *pOrigTemporaryMap, MATCHMAP *pTemporaryMap)
{
	int link_types[] = { CREF_FROM, CALL, DREF_FROM }; //CREF_TO, DREF_TO
	int processed_count = 0;
	multimap <va_t, MatchData>::iterator match_map_iter;
	MATCHMAP *pMatchMap = new MATCHMAP;

	LogMessage(0, __FUNCTION__, "Current match count=%u\n", pTemporaryMap->size());

	for (match_map_iter = pTemporaryMap->begin(); match_map_iter != pTemporaryMap->end(); match_map_iter++)
	{
		for (int i = 0; i < sizeof(link_types) / sizeof(int); i++)
		{
			int match_rate_info_count = 0;
			MatchRateInfo *p_match_rate_info_array = GetMatchRateInfoArray(match_map_iter->first, match_map_iter->second.Addresses[1], link_types[i], match_rate_info_count);

			if (!p_match_rate_info_array)
			{
				continue;
			}

			while (1)
			{
				int max_match_rate = 0;
				int selected_index = -1;

				for (int i = 0; i < match_rate_info_count; i++)
				{
					if (p_match_rate_info_array[i].MatchRate > max_match_rate)
					{
						max_match_rate = p_match_rate_info_array[i].MatchRate;
						selected_index = i;
					}
				}

				if (selected_index == -1)
					break;

				int min_index_diff = 0xFFFFFFF;
				for (int i = 0; i < match_rate_info_count; i++)
				{
					if (p_match_rate_info_array[i].MatchRate == max_match_rate)
					{
						if (p_match_rate_info_array[i].IndexDiff < min_index_diff)
						{
							min_index_diff = p_match_rate_info_array[i].IndexDiff;
							selected_index = i;
						}
					}
				}

				bool add_match_map = TRUE;
				MATCHMAP *p_compared_match_map[] = {
					pMainMatchMap,
					pOrigTemporaryMap,
					pMatchMap,
					pTemporaryMap
                };

				multimap <va_t, MatchData>::iterator it;
				for (int compare_i = 0; compare_i < sizeof(p_compared_match_map) / sizeof(p_compared_match_map[0]); compare_i++)
				{
					it = p_compared_match_map[compare_i]->find(p_match_rate_info_array[selected_index].Source);

					while (it != p_compared_match_map[compare_i]->end() &&
						it->first == p_match_rate_info_array[selected_index].Source
						)
					{
						if (it->second.Addresses[1] == p_match_rate_info_array[selected_index].Target)
						{
							if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(p_match_rate_info_array[selected_index].Source, p_match_rate_info_array[selected_index].Target))
							{
								LogMessage(0, __FUNCTION__, "Trying to add %X-%X: %d%%\n",
									p_match_rate_info_array[selected_index].Source,
									p_match_rate_info_array[selected_index].Target,
									p_match_rate_info_array[selected_index].MatchRate);

								LogMessage(0, __FUNCTION__, "\tAnother match is already there %X-%X\n",
									p_match_rate_info_array[selected_index].Source,
									p_match_rate_info_array[selected_index].Target);
							}

							add_match_map = FALSE;
							break;
						}
						else if (p_match_rate_info_array[selected_index].MatchRate <= it->second.MatchRate)
						{
							if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(p_match_rate_info_array[selected_index].Source, it->second.Addresses[1]))
							{
								LogMessage(0, __FUNCTION__, "Trying to add %X-%X: %d%%\n",
									p_match_rate_info_array[selected_index].Source,
									p_match_rate_info_array[selected_index].Target,
									p_match_rate_info_array[selected_index].MatchRate);
								LogMessage(0, __FUNCTION__, "\tAnother match is already there with higher or equal match rate %X-%X( %u%% )\n",
									p_match_rate_info_array[selected_index].Source,
									it->second.Addresses[1]);
							}

							add_match_map = FALSE;
							break;
						}
						it++;
					}

					if (!add_match_map)
						break;
				}

				if (add_match_map)
				{
					MatchData match_data;
					memset(&match_data, 0, sizeof(MatchData));
					match_data.Type = TREE_MATCH;
					match_data.SubType = i;
					match_data.Addresses[0] = p_match_rate_info_array[selected_index].Source;
					match_data.Addresses[1] = p_match_rate_info_array[selected_index].Target;
					match_data.MatchRate = p_match_rate_info_array[selected_index].MatchRate;
					match_data.UnpatchedParentAddress = match_map_iter->first;
					match_data.PatchedParentAddress = match_map_iter->second.Addresses[1];

					if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
					{
						LogMessage(0, __FUNCTION__, "%X-%X: %d%%\n", match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);
						LogMessage(0, __FUNCTION__, "\tParent %X-%X (link type: %d, match_rate_info_count:%d)\n", match_map_iter->first, match_map_iter->second.Addresses[1], link_types[i], match_rate_info_count);
					}

					pMatchMap->insert(MatchMap_Pair(match_data.Addresses[0], match_data));

					for (int i = 0; i < match_rate_info_count; i++)
					{
						if (p_match_rate_info_array[i].Source == p_match_rate_info_array[selected_index].Source ||
							p_match_rate_info_array[i].Target == p_match_rate_info_array[selected_index].Target
							)
						{
							p_match_rate_info_array[i].MatchRate = 0;
						}
					}
				}
				else
				{
					p_match_rate_info_array[selected_index].MatchRate = 0;
				}
			}

			delete p_match_rate_info_array;
		}

		processed_count++;

		if (processed_count % 100 == 0 || processed_count == pTemporaryMap->size())
		{
			LogMessage(0, __FUNCTION__, "%u/%u Items processed and produced %u match entries.\n",
				processed_count,
				pTemporaryMap->size(),
				pMatchMap->size()
			);
		}
	}

	LogMessage(0, __FUNCTION__, "New Tree Match count=%u\n", pMatchMap->size());
	return pMatchMap;
}

MATCHMAP *DiffAlgorithms::DoFunctionMatch(MATCHMAP *pCurrentMatchMap, multimap <va_t, va_t> *functionMembersMapForSource, multimap <va_t, va_t> *functionMembersMapForTarget)
{
    MATCHMAP *pMatchMap = new MATCHMAP;
	multimap <va_t, va_t>::iterator FunctionMembersIter;

	va_t SourceFunctionAddress = 0;
	list <va_t> SourceBlockAddresses;
	for (multimap <va_t, va_t>::iterator SourceFunctionMembersIter = functionMembersMapForSource->begin();; SourceFunctionMembersIter++)
	{
		if (SourceFunctionMembersIter == functionMembersMapForSource->end() || SourceFunctionAddress != SourceFunctionMembersIter->first)
		{
			//SourceFunctionAddress, SourceBlockAddresses
			unordered_set <va_t> targetFunctionAddresses;
			for (multimap <va_t, MatchData>::iterator matchMapIterator = pCurrentMatchMap->find(SourceFunctionAddress);
				matchMapIterator != pCurrentMatchMap->end() &&
				matchMapIterator->first == SourceFunctionAddress;
				matchMapIterator++)
			{
				//targetFunctionAddress, TargetBlockAddresses
				va_t targetFunctionAddress = matchMapIterator->second.Addresses[1];
				if (targetFunctionAddresses.find(targetFunctionAddress) == targetFunctionAddresses.end())
					continue;

				targetFunctionAddresses.insert(targetFunctionAddress);
				multimap <va_t, va_t>::iterator TargetFunctionMembersIter;
				list <va_t> TargetBlockAddresses;
				for (TargetFunctionMembersIter = functionMembersMapForTarget->find(targetFunctionAddress);
					TargetFunctionMembersIter != functionMembersMapForTarget->end() &&
					TargetFunctionMembersIter->first == targetFunctionAddress;
					TargetFunctionMembersIter++)
				{
					TargetBlockAddresses.push_back(TargetFunctionMembersIter->second);
				}
				DoInstructionHashMatchInsideFunction(SourceFunctionAddress, SourceBlockAddresses, targetFunctionAddress, TargetBlockAddresses);
				TargetBlockAddresses.clear();
			}
			targetFunctionAddresses.clear();
			SourceBlockAddresses.clear();
			if (SourceFunctionMembersIter == functionMembersMapForSource->end())
				break;
			else
				SourceFunctionAddress = SourceFunctionMembersIter->first;
		}
		SourceBlockAddresses.push_back(SourceFunctionMembersIter->second);
	}

	list <va_t> block_addresses;
	va_t source_function_addr = 0;
	for (FunctionMembersIter = functionMembersMapForSource->begin();; FunctionMembersIter++)
	{
		if (FunctionMembersIter == functionMembersMapForSource->end() || source_function_addr != FunctionMembersIter->first)
		{
			//Analyze Function, block_addresses contains all the members
			unordered_map <va_t, va_t> function_match_count;
			if (source_function_addr != 0)
			{
				for (va_t block_address : block_addresses)
				{
					if (m_pdumpAddressChecker && (m_pdumpAddressChecker->IsDumpPair(block_address, 0) || m_pdumpAddressChecker->IsDumpPair(source_function_addr, 0)))
						LogMessage(0, __FUNCTION__, "Function: %X Block: %X\r\n", source_function_addr, block_address);

					for (multimap <va_t, MatchData>::iterator match_map_it = pCurrentMatchMap->find(block_address);
						match_map_it != pCurrentMatchMap->end() && match_map_it->first == block_address;
						match_map_it++)
					{
						va_t target_addr = match_map_it->second.Addresses[1];
						if (m_pdumpAddressChecker && (m_pdumpAddressChecker->IsDumpPair(block_address, target_addr) || m_pdumpAddressChecker->IsDumpPair(source_function_addr, 0)))
							LogMessage(0, __FUNCTION__, "Function: %X Block: %X:%X\r\n", source_function_addr, match_map_it->second.Addresses[0], target_addr);

						va_t target_function_address;
						if (TargetLoader->GetFunctionAddress(target_addr, target_function_address))
						{
							if (m_pdumpAddressChecker && (m_pdumpAddressChecker->IsDumpPair(block_address, target_addr) || m_pdumpAddressChecker->IsDumpPair(source_function_addr, target_function_address)))
								LogMessage(0, __FUNCTION__, "Function: %X:%X Block: %X:%X\r\n", source_function_addr, target_function_address, block_address, target_addr);

							unordered_map <va_t, va_t>::iterator function_match_count_it = function_match_count.find(target_function_address);
							if (function_match_count_it == function_match_count.end())
							{
								function_match_count.insert(pair<va_t, va_t>(target_function_address, 1));
							}
							else
							{
								function_match_count_it->second++;
							}
						}
					}
				}
				//source_function_addr
				//We have function_match_count filled up!
				//Get Maximum value in function_match_count
				va_t maximum_function_match_count = 0;
				va_t chosen_target_function_addr = 0;

				for (auto& val : function_match_count)
				{
					if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(source_function_addr, val.first))
						LogMessage(0, __FUNCTION__, "%X:%X( %u )\n", source_function_addr, val.first, val.second);

					if (maximum_function_match_count < val.second)
					{
						LogMessage(0, __FUNCTION__, " New maximum function match count: %d over %d\n", val.second, maximum_function_match_count);
						chosen_target_function_addr = val.first;
						maximum_function_match_count = val.second;
					}
				}

				if (chosen_target_function_addr)
				{
					//Remove Except chosen_target_function_addr from match_map
					if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(source_function_addr, chosen_target_function_addr))
						LogMessage(0, __FUNCTION__, "Choosing ( %X:%X )\n", source_function_addr, chosen_target_function_addr);

					if (pCurrentMatchMap->find(source_function_addr) == pCurrentMatchMap->end())
					{
						MatchData match_data;
						memset(&match_data, 0, sizeof(MatchData));
						match_data.Type = FUNCTION_MATCH;
						match_data.Addresses[0] = source_function_addr;
						match_data.Addresses[1] = chosen_target_function_addr;
						match_data.MatchRate = 100;

						if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
							LogMessage(0, __FUNCTION__, "%s adding to temporary map %X-%X: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

						pMatchMap->insert(MatchMap_Pair(match_data.Addresses[0], match_data));
					}
				}

				block_addresses.clear();
				function_match_count.clear();
				//AddressToFunctionMap.clear();
			}

			if (FunctionMembersIter == functionMembersMapForSource->end())
				break;
			else
				source_function_addr = FunctionMembersIter->first;
		}
		if (FunctionMembersIter == functionMembersMapForSource->end())
			break;

		//Collect BlockAddresses
		block_addresses.push_back(FunctionMembersIter->second);
	}

    return pMatchMap;
}

const char* MatchDataTypeStr[] = { "Name", "InstructionHash", "Two Level InstructionHash", "IsoMorphic Match", "InstructionHash Inside Function", "Function" };

void DiffAlgorithms::DumpMatchMapIterInfo(const char *prefix, multimap <va_t, MatchData>::iterator match_map_iter)
{
	const char *SubTypeStr[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };

	Logger.Log(11, LOG_DIFF_MACHINE, "%s: match: %X - %X ( %s/%s ) from: %X %X ( Match rate=%u/100 ) Status=%X\n",
		prefix,
		match_map_iter->first,
		match_map_iter->second.Addresses[1],
		MatchDataTypeStr[match_map_iter->second.Type],
		(match_map_iter->second.Type == TREE_MATCH && match_map_iter->second.SubType < sizeof(SubTypeStr) / sizeof(char*)) ? SubTypeStr[match_map_iter->second.SubType] : "None",
		match_map_iter->second.UnpatchedParentAddress,
		match_map_iter->second.PatchedParentAddress,
		match_map_iter->second.MatchRate,
		match_map_iter->second.Status);
}

const char* DiffAlgorithms::GetMatchTypeStr(int Type)
{
	if (Type < sizeof(MatchDataTypeStr) / sizeof(MatchDataTypeStr[0]))
	{
		return MatchDataTypeStr[Type];
	}
	return "Unknown";
}
