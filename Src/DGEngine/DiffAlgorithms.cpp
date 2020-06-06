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
