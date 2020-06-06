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

void DiffAlgorithms::RemoveDuplicates(MATCHMAP *p_matchMap)
{
	multimap <va_t, MatchData>::iterator match_map_iter;
	multimap <va_t, MatchData>::iterator found_match_map_iter;
	multimap <va_t, MatchData>::iterator max_match_map_iter;
	for (match_map_iter = p_matchMap->begin();
		match_map_iter != p_matchMap->end();
		match_map_iter++)
	{
		if (match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
			continue;
		int found_duplicate = FALSE;
		max_match_map_iter = match_map_iter;
		int maximum_matchrate = match_map_iter->second.MatchRate;
		for (found_match_map_iter = p_matchMap->find(match_map_iter->first);
			found_match_map_iter != p_matchMap->end() && match_map_iter->first == found_match_map_iter->first;
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
			Dump_matchMapIterInfo( __FUNCTION__, max_match_map_iter );
			for ( found_match_map_iter=DiffResults->MatchMap.find( match_map_iter->first );
				found_match_map_iter!=DiffResults->MatchMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++ )
			{
				if( max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
				{
					if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Removing %X %X match\n", found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );
					Dump_matchMapIterInfo( __FUNCTION__, found_match_map_iter );
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
			Dump_matchMapIterInfo( __FUNCTION__, max_match_map_iter );
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
					Dump_matchMapIterInfo( __FUNCTION__, found_match_map_iter );
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

void DiffAlgorithms::RevokeTreeMatchMapIterInfo(MATCHMAP *p_matchMap, va_t address, va_t match_address)
{
	return;
	multimap <va_t, MatchData>::iterator match_map_iter;
	for (match_map_iter = p_matchMap->begin();
		match_map_iter != p_matchMap->end();
		match_map_iter++)
	{
		if (match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
			continue;
		if (match_map_iter->second.Type == TREE_MATCH)
		{
			if (match_map_iter->second.UnpatchedParentAddress == address && match_map_iter->second.PatchedParentAddress == match_address)
			{
				match_map_iter->second.Status |= STATUS_MAPPING_DISABLED;
				RevokeTreeMatchMapIterInfo(p_matchMap, match_map_iter->first, match_map_iter->second.Addresses[1]);
			}
		}
	}
}


/*REMOVE:
BOOL DiffAlgorithms::DeleteMatchInfo(DiffStorage & diffStorage)
{
	if (sourceFunctionAddress > 0 && targetFunctionAddress > 0)
	{
		m_psourceBinary->DeleteMatchInfo(&diffStorage, m_psourceBinary->GetFileID(), sourceFunctionAddress);
		m_ptargetBinary->DeleteMatchInfo(&diffStorage, m_ptargetBinary->GetFileID(), targetFunctionAddress);
	}
	else
	{
		diffStorage.DeleteMatches(m_psourceBinary->GetFileID(), m_ptargetBinary->GetFileID());
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
		multimap <va_t, unsigned char*>::iterator addressToInstructionHashMap_Iter;
		addressToInstructionHashMap_Iter = m_psourceBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.find(match_map_iter->second.Addresses[0]);
		if (addressToInstructionHashMap_Iter != m_psourceBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.end())
		{
			m_psourceBinary->GetClientDisassemblyHashMaps()->instructionHashMap.erase(addressToInstructionHashMap_Iter->second);
		}
		addressToInstructionHashMap_Iter = m_ptargetBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.find(match_map_iter->second.Addresses[1]);
		if (addressToInstructionHashMap_Iter != m_ptargetBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.end())
		{
			m_ptargetBinary->GetClientDisassemblyHashMaps()->instructionHashMap.erase(addressToInstructionHashMap_Iter->second);
		}
	}

	LogMessage(0, __FUNCTION__, "%u-%u\n",
		m_psourceBinary->GetClientDisassemblyHashMaps()->instructionHashMap.size(),
		m_ptargetBinary->GetClientDisassemblyHashMaps()->instructionHashMap.size());
}

MATCHMAP *DiffAlgorithms::DoFunctionMatch(
    MATCHMAP *pCurrentMatchMap,
    multimap <va_t, va_t> *functionMembersMapForSource,
    multimap <va_t, va_t> *functionMembersMapForTarget
)
{
    MATCHMAP *p_matchMap = new MATCHMAP;
	multimap <va_t, va_t>::iterator functionMembersIterator;

	va_t sourceFunctionAddress = 0;
	list <va_t> sourceFunctionAddresses;
	for (multimap <va_t, va_t>::iterator SourcefunctionMembersIterator = functionMembersMapForSource->begin();; SourcefunctionMembersIterator++)
	{
		if (SourcefunctionMembersIterator == functionMembersMapForSource->end() || sourceFunctionAddress != SourcefunctionMembersIterator->first)
		{
			//sourceFunctionAddress, sourceFunctionAddress
			unordered_set <va_t> targetFunctionAddresses;
			for (multimap <va_t, MatchData>::iterator matchMapIterator = pCurrentMatchMap->find(sourceFunctionAddress);
				matchMapIterator != pCurrentMatchMap->end() &&
				matchMapIterator->first == sourceFunctionAddress;
				matchMapIterator++)
			{
				//targetFunctionAddress, TargetBlockAddresses
				va_t targetFunctionAddress = matchMapIterator->second.Addresses[1];
				if (targetFunctionAddresses.find(targetFunctionAddress) == targetFunctionAddresses.end())
					continue;

				targetFunctionAddresses.insert(targetFunctionAddress);
				multimap <va_t, va_t>::iterator TargetfunctionMembersIterator;
				list <va_t> TargetBlockAddresses;
				for (TargetfunctionMembersIterator = functionMembersMapForTarget->find(targetFunctionAddress);
					TargetfunctionMembersIterator != functionMembersMapForTarget->end() &&
					TargetfunctionMembersIterator->first == targetFunctionAddress;
					TargetfunctionMembersIterator++)
				{
					TargetBlockAddresses.push_back(TargetfunctionMembersIterator->second);
				}
				DoInstructionHashMatchInsideFunction(sourceFunctionAddress, sourceFunctionAddress, targetFunctionAddress, TargetBlockAddresses);
				TargetBlockAddresses.clear();
			}
			targetFunctionAddresses.clear();
			sourceFunctionAddresses.clear();
			if (SourcefunctionMembersIterator == functionMembersMapForSource->end())
				break;
			else
				sourceFunctionAddress = SourcefunctionMembersIterator->first;
		}
		sourceFunctionAddresses.push_back(SourcefunctionMembersIterator->second);
	}

	list <va_t> blockAddresses;
	for (functionMembersIterator = functionMembersMapForSource->begin();; functionMembersIterator++)
	{
		if (functionMembersIterator == functionMembersMapForSource->end() || sourceFunctionAddress != functionMembersIterator->first)
		{
			//Analyze Function, blockAddresses contains all the members
			unordered_map <va_t, va_t> function_match_count;
			if (sourceFunctionAddress != 0)
			{
				for (va_t block_address : blockAddresses)
				{
					for (multimap <va_t, MatchData>::iterator match_map_it = pCurrentMatchMap->find(block_address);
						match_map_it != pCurrentMatchMap->end() && match_map_it->first == block_address;
						match_map_it++)
					{
						va_t targetAddress = match_map_it->second.Addresses[1];
						va_t targetFunctionAddress;
						if (m_ptargetBinary->GetFunctionAddress(targetAddress, targetFunctionAddress))
						{
							unordered_map <va_t, va_t>::iterator function_match_count_it = function_match_count.find(targetFunctionAddress);
							if (function_match_count_it == function_match_count.end())
							{
								function_match_count.insert(pair<va_t, va_t>(targetFunctionAddress, 1));
							}
							else
							{
								function_match_count_it->second++;
							}
						}
					}
				}
				//sourceFunctionAddress
				//We have function_match_count filled up!
				//Get Maximum value in function_match_count
				va_t maximum_function_match_count = 0;
				va_t chosen_target_function_addr = 0;

				for (auto& val : function_match_count)
				{
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
					if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(sourceFunctionAddress, chosen_target_function_addr))
						LogMessage(0, __FUNCTION__, "Choosing ( %X:%X )\n", sourceFunctionAddress, chosen_target_function_addr);

					if (pCurrentMatchMap->find(sourceFunctionAddress) == pCurrentMatchMap->end())
					{
						MatchData match_data;
						memset(&match_data, 0, sizeof(MatchData));
						match_data.Type = FUNCTION_MATCH;
						match_data.Addresses[0] = sourceFunctionAddress;
						match_data.Addresses[1] = chosen_target_function_addr;
						match_data.MatchRate = 100;

						if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
							LogMessage(0, __FUNCTION__, "%s adding to temporary map %X-%X: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

						p_matchMap->insert(MatchMap_Pair(match_data.Addresses[0], match_data));
					}
				}

				blockAddresses.clear();
				function_match_count.clear();
				//AddressToFunctionMap.clear();
			}

			if (functionMembersIterator == functionMembersMapForSource->end())
				break;
			else
				sourceFunctionAddress = functionMembersIterator->first;
		}
		if (functionMembersIterator == functionMembersMapForSource->end())
			break;

		//Collect BlockAddresses
		blockAddresses.push_back(functionMembersIterator->second);
	}

    return p_matchMap;
}

const char* MatchDataTypeStr[] = { "Name", "InstructionHash", "Two Level InstructionHash", "IsoMorphic Match", "InstructionHash Inside Function", "Function" };

void DiffAlgorithms::Dump_matchMapIterInfo(const char *prefix, multimap <va_t, MatchData>::iterator match_map_iter)
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
