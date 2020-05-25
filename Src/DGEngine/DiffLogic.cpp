#include <string>
#include <list>
#include <unordered_set>
#include <unordered_map>
#include <stdlib.h>
#include <tchar.h>
#include <malloc.h>
#include "sqlite3.h"

#include "Diff.h"
#include "DiffLogic.h"
#include "SQLiteDiffStorage.h"
#include "SQLiteDisassemblyStorage.h"

using namespace std;
using namespace stdext;
#include "Configuration.h"

extern LogOperation Logger;

DiffLogic::DiffLogic(Binary *the_source, Binary *the_target) :
    DebugFlag(0),
    m_psourceBinary(NULL),
    m_ptargetBinary(NULL),
    SourceID(0),
    m_sourceFunctionAddress(0),
    TargetID(0),
    m_targetFunctionAddress(0),
    m_bloadMaps(false),
    LoadMatchResults(true),
    ShowFullMatched(false),
    ShowNonMatched(false),
    m_pdumpAddressChecker(NULL)
{
    m_pdiffStorage = NULL;
    
    SetSource(the_source);
    SetTarget(the_target);
	m_pMatchResults = NULL;
	m_pdiffAlgorithms = new DiffAlgorithms();
}

DiffLogic::~DiffLogic()
{
    m_pFunctionMatchInfoList->ClearFunctionMatchList();

    if (m_psourceBinary)
        delete m_psourceBinary;

    if (m_ptargetBinary)
        delete m_ptargetBinary;

	if (m_pMatchResults)
	{
		m_pMatchResults->Clear();
		delete m_pMatchResults;
	}        
}

Binary *DiffLogic::GetSourceBinary()
{
    return m_psourceBinary;
}

Binary *DiffLogic::GetTargetBinary()
{
    return m_ptargetBinary;
}

void DiffLogic::AnalyzeFunctionSanity()
{
    va_t last_unpatched_addr = 0;
    va_t last_patched_addr = 0;
    va_t unpatched_addr = 0;
    va_t patched_addr = 0;

    Logger.Log(10, LOG_DIFF_MACHINE, "%s: DiffResults->MatchMap Size=%u\n", __FUNCTION__, m_pMatchResults->MatchMap.size());
    for (auto& val : m_pMatchResults->MatchMap)
    {
        PBasicBlock p_basic_block = m_psourceBinary->GetBasicBlock(val.first);
        if (p_basic_block)
        {
            unpatched_addr = val.first;
            patched_addr = val.second.Addresses[1];
            if (last_unpatched_addr != unpatched_addr &&
                last_patched_addr != patched_addr
                )
            {
                if (p_basic_block->BlockType == FUNCTION_BLOCK)
                {
                }
                else
                {
                }
            }
            if (last_unpatched_addr == unpatched_addr &&
                last_patched_addr != patched_addr
                )
            {
                Logger.Log(10, LOG_DIFF_MACHINE, "%s: *** *Multiple Possibilities\n", __FUNCTION__);
            }

            last_unpatched_addr = unpatched_addr;
            last_patched_addr = patched_addr;
            free(p_basic_block);
        }
    }

    for (auto& val : m_pMatchResults->ReverseAddressMap)
    {
        PBasicBlock p_basic_block = m_psourceBinary->GetBasicBlock(val.first);
        if (p_basic_block)
        {
            unpatched_addr = val.first;
            patched_addr = val.second;

            if (last_unpatched_addr != unpatched_addr &&
                last_patched_addr != patched_addr)
            {
                if (p_basic_block->BlockType == FUNCTION_BLOCK)
                {
                }
                else
                {
                }
            }
            if (last_unpatched_addr == unpatched_addr &&
                last_patched_addr != patched_addr
                )
            {
                Logger.Log(10, LOG_DIFF_MACHINE, "%s: *** *Multiple Possibilities\n", __FUNCTION__);
            }
            else
            {
            }
            last_unpatched_addr = unpatched_addr;
            last_patched_addr = patched_addr;

            free(p_basic_block);
        }
    }
}

void DiffLogic::TestFunctionMatchRate(int index, va_t Address)
{
    Binary *ClientManager = index == 0 ? m_psourceBinary : m_ptargetBinary;
    for (auto& val : ClientManager->GetFunctionBasicBlocks(Address))
    {
        MatchMapList *pMatchMapList = GetMatchData(index, val.Start);
        pMatchMapList->Print();
        pMatchMapList->FreeMatchMapList();
    }
}

void DiffLogic::RetrieveNonMatchingMembers(int index, va_t FunctionAddress, list <va_t> & Members)
{
    Binary *ClientManager = index == 0 ? m_psourceBinary : m_ptargetBinary;
    list <AddressRange> address_list = ClientManager->GetFunctionBasicBlocks(FunctionAddress);

    for (auto& val : address_list)
    {
        MatchMapList *pMatchMapList = GetMatchData(index, val.Start);
        if(pMatchMapList->GetMaxMatchRate() < 100)
        {
            Members.push_back(val.Start);
        }
        pMatchMapList->FreeMatchMapList();
    }
}

bool DiffLogic::TestAnalysis()
{
    return TRUE;
}

void DumpAddressChecker::AddSrcDumpAddress(va_t address)
{
    SrcDumpAddresses.insert(address);
}

void DumpAddressChecker::AddTargetDumpAddress(va_t address)
{
    TargetDumpAddresses.insert(address);
}

bool DumpAddressChecker::IsDumpPair(va_t src, va_t target)
{
    if ((SrcDumpAddresses.size() == 0 && TargetDumpAddresses.size() == 0) ||
        SrcDumpAddresses.find(src) != SrcDumpAddresses.end() ||
        TargetDumpAddresses.find(target) != TargetDumpAddresses.end()
        )
    {
        return true;
    }
    return false;
}

void DumpAddressChecker::DumpMatchInfo(va_t src, va_t target, int match_rate, const char *format, ...)
{
    if (IsDumpPair(src, target))
    {
        Logger.Log(10, LOG_DIFF_MACHINE, format);
        Logger.Log(10, LOG_DIFF_MACHINE, "\t%X %X (%d%%)\n", src, target, match_rate);
    }
}


MATCHMAP *DiffLogic::DoFunctionLevelMatchOptimizing(FunctionMatchInfoList *pFunctionMatchInfoList)
{
    MATCHMAP *pMatchMap = new MATCHMAP;

	if (DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING)
		LogMessage(0, __FUNCTION__, "%s: DoFunctionLevelMatchOptimizing\n", __FUNCTION__);

    for (auto& val : *pFunctionMatchInfoList)
	{
		Logger.Log(11, LOG_DIFF_MACHINE,
			"Source FileID: 0x%.8x\n"
			"Target FileID: 0x%.8x\n"
			"SourceAddress : 0x%.8x\n"
			"EndAddress : 0x%.8x\n"
			"TargetAddress : 0x%.8x\n"
			"BlockType : 0x%.8x\n"
			"MatchRate : 0x%.8x\n"
			"SourceFunctionName : %s\n"
			"Type : 0x%.8x\n"
			"TargetFunctionName : %s\n"
			"MatchCountForTheSource : 0x%.8x\n"
			"NoneMatchCountForTheSource : 0x%.8x\n"
			"MatchCountWithModificationForTheSource : 0x%.8x\n"
			"MatchCountForTheTarget : 0x%.8x\n"
			"NoneMatchCountForTheTarget : 0x%.8x\n"
			"MatchCountWithModificationForTheTarget: 0x%.8x\n"
			"\r\n",
			m_psourceBinary->GetFileID(),
			m_ptargetBinary->GetFileID(),
			val.SourceAddress,
			val.EndAddress,
			val.TargetAddress,
			val.BlockType,
			val.MatchRate,
			val.SourceFunctionName,
			val.Type,
			val.TargetFunctionName,
			val.MatchCountForTheSource,
			val.NoneMatchCountForTheSource,
			val.MatchCountWithModificationForTheSource,
			val.MatchCountForTheTarget,
			val.NoneMatchCountForTheTarget,
			val.MatchCountWithModificationForTheTarget
		);
		if (DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING)
		{
			LogMessage(0, __FUNCTION__, "* *Unpatched:\n");
			TestFunctionMatchRate(0, val.SourceAddress);

			LogMessage(0, __FUNCTION__, "* *Patched:\n");
			TestFunctionMatchRate(1, val.TargetAddress);
		}

		list <va_t> sourceMembers;
		RetrieveNonMatchingMembers(0, val.SourceAddress, sourceMembers);

		list <va_t> targetMembers;
		RetrieveNonMatchingMembers(1, val.TargetAddress, targetMembers);

		if (DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING)
		{
			LogMessage(0, __FUNCTION__, "Source Members\n");
            for (va_t address : sourceMembers)
			{
				LogMessage(0, __FUNCTION__, "0x%X, ", address);
			}
			LogMessage(0, __FUNCTION__, "\n");

			LogMessage(0, __FUNCTION__, "Target Members\n");
            for (va_t address : targetMembers)
			{
				LogMessage(0, __FUNCTION__, "0x%X, ", address);
			}
			LogMessage(0, __FUNCTION__, "\n");
		}

        for (va_t sourceAddress : sourceMembers)
		{
            for (va_t targetAddress : targetMembers)
			{
				bool debug = false;
				if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair(sourceAddress, targetAddress))
					debug = true;

				int currentMatchRate = GetMatchRate(sourceAddress, targetAddress);
				if (debug)
					LogMessage(0, __FUNCTION__, "Try to insert %X-%X: %d%%\n", sourceAddress, targetAddress, currentMatchRate);

                MatchData match_data;
                memset(&match_data, 0, sizeof(MatchData));
                match_data.Type = INSTRUCTION_HASH_INSIDE_FUNCTION_MATCH;
                match_data.SubType = 0;
                match_data.Addresses[0] = sourceAddress;
                match_data.Addresses[1] = targetAddress;

                match_data.UnpatchedParentAddress = 0;
                match_data.PatchedParentAddress = 0;
                match_data.MatchRate = currentMatchRate;

                pMatchMap->insert(MatchMap_Pair(match_data.Addresses[0], match_data));
			}
		}

	}
	return pMatchMap;
}

bool DiffLogic::Analyze()
{
    MATCHMAP TemporaryMatchMap;

    if (!m_psourceBinary || !m_ptargetBinary)
        return FALSE;

    m_pMatchResults = new MatchResults();
    m_pMatchResults->SetDumpAddressChecker(m_pdumpAddressChecker);

    Logger.Log(10, LOG_DIFF_MACHINE, "%s: InstructionHash Map Size %u:%u\n", __FUNCTION__,
        m_psourceBinary->GetClientDisassemblyHashMaps()->instructionHashMap.size(),
        m_ptargetBinary->GetClientDisassemblyHashMaps()->instructionHashMap.size());

    // Symbol Match
    Logger.Log(10, LOG_DIFF_MACHINE, "Symbol Match\n");

    multimap <string, va_t>::iterator patchedNameMapIterator;

    for (auto& val : m_psourceBinary->GetClientDisassemblyHashMaps()->symbolMap)
    {
        if (m_psourceBinary->GetClientDisassemblyHashMaps()->symbolMap.count(val.first) == 1)
        {
            //unique key
            if (m_ptargetBinary->GetClientDisassemblyHashMaps()->symbolMap.count(val.first) == 1)
            {
                if (val.first.find("loc_") != string::npos ||
                    val.first.find("locret_") != string::npos ||
                    val.first.find("sub_") != string::npos ||
                    val.first.find("func_") != string::npos)
                    continue;

                patchedNameMapIterator = m_ptargetBinary->GetClientDisassemblyHashMaps()->symbolMap.find(val.first);

                if (patchedNameMapIterator != m_ptargetBinary->GetClientDisassemblyHashMaps()->symbolMap.end())
                {
                    MatchData match_data;
                    memset(&match_data, 0, sizeof(MatchData));
                    match_data.Type = NAME_MATCH;
                    match_data.Addresses[0] = val.second;
                    match_data.Addresses[1] = patchedNameMapIterator->second;
                    match_data.MatchRate = GetMatchRate(
                        val.second,
                        patchedNameMapIterator->second
                    );

                    if (m_pdumpAddressChecker)
                        m_pdumpAddressChecker->DumpMatchInfo(match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate, "%s Add to temporary match map", __FUNCTION__);

                    TemporaryMatchMap.insert(MatchMap_Pair(
                        val.second,
                        match_data
                    ));
                }
            }
        }
    }
    Logger.Log(10, LOG_DIFF_MACHINE, "Symbol Match Ended\n");

    Logger.Log(10, LOG_DIFF_MACHINE, "%s: Symbol Matched number=%u\n", __FUNCTION__, TemporaryMatchMap.size());

    int OldMatchMapSize = 0;
    while (1)
    {
        Logger.Log(10, LOG_DIFF_MACHINE, "%s: DoInstructionHashMatch\n", __FUNCTION__);

        MATCHMAP *pTemporaryMap = m_pdiffAlgorithms->DoInstructionHashMatch();
        Logger.Log(10, LOG_DIFF_MACHINE, "%s: Match Map Size: %u\n", __FUNCTION__, pTemporaryMap->size());
        Logger.Log(10, LOG_DIFF_MACHINE, "%s: DoIsomorphMatch\n", __FUNCTION__);
	    while (pTemporaryMap->size() > 0)
	    {
            MATCHMAP *pMatchMap = m_pdiffAlgorithms->DoIsomorphMatch(&m_pMatchResults->MatchMap, &TemporaryMatchMap, pTemporaryMap);

            if (pMatchMap->size() > 0)
            {
                //TODO: AppendToMatchMap(pOrigTemporaryMap, pMatchMap);
                //if (pTemporaryMap != pOrigTemporaryMap)
                //{
                //    pTemporaryMap->clear();
                //    delete pTemporaryMap;
                //}

                //pTemporaryMap = pMatchMap;
            }
            else
            {
                pMatchMap->clear();
                delete pMatchMap;
                break;
            }            
        }

        Logger.Log(10, LOG_DIFF_MACHINE, "%s: Match Map Size: %u\n", __FUNCTION__, TemporaryMatchMap.size());

        if (TemporaryMatchMap.size() > 0)
        {
            m_pMatchResults->Append(&TemporaryMatchMap);
        }
        else
        {
            break;
        }
        m_pdiffAlgorithms->PurgeInstructionHashHashMap(&TemporaryMatchMap);
        TemporaryMatchMap.clear();

        Logger.Log(10, LOG_DIFF_MACHINE, "%s: Call DoFunctionMatch\n", __FUNCTION__);

		m_psourceBinary->LoadBlockFunctionMaps();
		m_ptargetBinary->LoadBlockFunctionMaps();

        MATCHMAP *pFunctionMatchMap = m_pdiffAlgorithms->DoFunctionMatch(&m_pMatchResults->MatchMap, m_psourceBinary->GetFunctionToBlock(), m_ptargetBinary->GetFunctionToBlock());

        /*TODO: Against pFUnctionMatchMap

        // Remove match entries for specific target_function
        for (block_addr_it = block_addresses.begin(); block_addr_it != block_addresses.end(); block_addr_it++)
        {
            va_t sourceAddress = *block_addr_it;
            for (multimap <va_t, MatchData>::iterator it = pCurrentMatchMap->find(sourceAddress);
                it != pCurrentMatchMap->end() && it->first == sourceAddress;
                )
            {
                va_t sourceFunctionAddress;
                va_t targetAddress = it->second.Addresses[1];
                BOOL function_matched = FALSE;
                if (m_psourceBinary->GetFunctionAddress(sourceAddress, sourceFunctionAddress))
                {
                    function_matched = m_ptargetBinary->IsFunctionBlock(targetAddress, chosenm_targetFunctionAddress);
                }

                if (!function_matched)
                {
                    if (m_pdumpAddressChecker &&
                        (
                            m_pdumpAddressChecker->IsDumpPair(sourceFunctionAddress, targetAddress) ||
                            m_pdumpAddressChecker->IsDumpPair(sourceFunctionAddress, chosenm_targetFunctionAddress)
                            )
                        )
                        LogMessage(0, __FUNCTION__, "Removing address %X( %X )-%X( %X )\n", sourceAddress, sourceFunctionAddress, targetAddress, chosenm_targetFunctionAddress);
                    it = m_pMatchResults->Erase(it);

                }
                else
                {
                    //Logger.Log( 10, LOG_DIFF_MACHINE,  "Keeping address %X( %X )-%X( %X )\n", Address, AddressToFunctionMapForTheSourceIter->second, targetAddress, AddressToFunctionMapForTheTargetIter->second );
                    it++;
                }
            }
        }
        */

		m_psourceBinary->ClearBlockFunctionMaps();
		m_ptargetBinary->ClearBlockFunctionMaps();

        Logger.Log(10, LOG_DIFF_MACHINE, "%s: One Loop Of Analysis MatchMap size is %u.\n", __FUNCTION__, m_pMatchResults->MatchMap.size());

        if (OldMatchMapSize == m_pMatchResults->MatchMap.size())
            break;

        OldMatchMapSize = m_pMatchResults->MatchMap.size();
    }

    m_pdiffAlgorithms->RemoveDuplicates(&m_pMatchResults->MatchMap);
	m_pMatchResults->CleanUp();

    m_pFunctionMatchInfoList->ClearFunctionMatchList();
    //AnalyzeFunctionSanity();
    FunctionMatchInfoList *pFunctionMatchInfo = m_pdiffAlgorithms->GenerateFunctionMatchInfo(&m_pMatchResults->MatchMap, &m_pMatchResults->ReverseAddressMap);
    MATCHMAP *pFunctionLevelOptionmizedMap = DoFunctionLevelMatchOptimizing(pFunctionMatchInfo);

    /* TODO: Iterate MATCHMAP and add to the main map
    bool add_current_entry = true;

    //Remove any existing entries with smaller match rate than current one
    MatchMapList *pMatchMapList = GetMatchData(0, *source_member_iter);
    if (pMatchMapList->size() > 0)
    {
        add_current_entry = false;
        for (vector<MatchData*>::iterator it = pMatchMapList->begin(); it != pMatchMapList->end(); it++)
        {
            const char *operation = "Retain";
            if ((*it)->MatchRate < currentMatchRate)
            {
                RemoveMatchData((*it)->Addresses[0], (*it)->Addresses[1]);
                add_current_entry = true;
                if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair((*it)->Addresses[0], (*it)->Addresses[1]))
                    debug = true;
                operation = "Remove";
            }

            if (debug)
                LogMessage(0, __FUNCTION__, "\t%s %X-%X: %d%%\n", operation, *source_member_iter, (*it)->Addresses[1], (*it)->MatchRate);
        }
        pMatchMapList->FreeMatchMapList();
    }

    pMatchMapList = GetMatchData(1, *target_member_iter);
    if (pMatchMapList->size() > 0)
    {
        add_current_entry = false;
        for (vector<MatchData*>::iterator it = pMatchMapList->begin(); it != pMatchMapList->end(); it++)
        {
            const char *operation = "Retain";
            if ((*it)->MatchRate < currentMatchRate)
            {
                RemoveMatchData((*it)->Addresses[0], (*it)->Addresses[1]);
                add_current_entry = true;
                if (m_pdumpAddressChecker && m_pdumpAddressChecker->IsDumpPair((*it)->Addresses[0], (*it)->Addresses[1]))
                    debug = true;
                operation = "Remove";
            }
            if (debug)
                LogMessage(0, __FUNCTION__, "\t%s %X-%X: %d%%\n", operation, (*it)->Addresses[0], *target_member_iter, (*it)->MatchRate);
        }
        pMatchMapList->FreeMatchMapList();
    }
    if (add_current_entry)
    {
        if (debug)
        {
            LogMessage(0, __FUNCTION__, " *Replacing existing match data entries...\n");
            LogMessage(0, __FUNCTION__, "\t%X-%X: %d%%\n", *source_member_iter, *target_member_iter, currentMatchRate);
        }
    }
    */

    m_pFunctionMatchInfoList = m_pdiffAlgorithms->GenerateFunctionMatchInfo(&m_pMatchResults->MatchMap, &m_pMatchResults->ReverseAddressMap);
    return true;
}

void DiffLogic::AppendToMatchMap(MATCHMAP  *pBaseMap, MATCHMAP  *pTemporaryMap)
{
    multimap <va_t, MatchData>::iterator matchMapIterator;

    Logger.Log(10, LOG_DIFF_MACHINE, "%s: Appending %u Items To MatchMap\n", __FUNCTION__, pTemporaryMap->size());
    for (matchMapIterator = pTemporaryMap->begin(); matchMapIterator != pTemporaryMap->end(); matchMapIterator++)
    {
        pBaseMap->insert(MatchMap_Pair(matchMapIterator->first, matchMapIterator->second));
    }
}

void DiffLogic::ShowDiffMap(va_t unpatched_address, va_t patched_address)
{
    va_t *p_addresses;

    list <va_t> address_list;
    unordered_set <va_t> checked_addresses;
    address_list.push_back(unpatched_address);
    checked_addresses.insert(unpatched_address);

    for (va_t address : address_list)
    {
        int addresses_number;
        Logger.Log(10, LOG_DIFF_MACHINE, "%s:  address=%X\n", __FUNCTION__, address);
        p_addresses = m_psourceBinary->GetCodeReferences(address, CREF_FROM, &addresses_number);
        if (p_addresses && addresses_number > 0)
        {
            Logger.Log(10, LOG_DIFF_MACHINE, "%s:  p_addresses=%X addresses_number=%u\n", __FUNCTION__, p_addresses, addresses_number);
            for (int i = 0; i < addresses_number; i++)
            {
                if (p_addresses[i])
                {
                    if (checked_addresses.find(p_addresses[i]) == checked_addresses.end())
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

int DiffLogic::GetMatchRate(va_t unpatched_address, va_t patched_address)
{
    multimap <va_t, unsigned char*>::iterator source_instructionHashMap_Iter;
    multimap <va_t, unsigned char*>::iterator target_instructionHashMap_Iter;

    source_instructionHashMap_Iter = m_psourceBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.find(unpatched_address);
    target_instructionHashMap_Iter = m_ptargetBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.find(patched_address);

    if (
        source_instructionHashMap_Iter != m_psourceBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.end() &&
        target_instructionHashMap_Iter != m_ptargetBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap.end()
        )
    {
        return m_pdiffAlgorithms->GetInstructionHashMatchRate(
            source_instructionHashMap_Iter->second,
            target_instructionHashMap_Iter->second);
    }
    return 0;
}

void DiffLogic::GetMatchStatistics(
    va_t address,
    int index,
    int& found_match_number,
    int& found_match_with_difference_number,
    int& not_found_match_number,
    float& match_rate
)
{
    bool debug = false;
    if (m_pdumpAddressChecker &&
        (
        (index == 0 && m_pdumpAddressChecker->IsDumpPair(address, 0)) ||
            (index == 1 && m_pdumpAddressChecker->IsDumpPair(0, address))
            )
        )
        debug = true;

    Binary *ClientManager = m_psourceBinary;

    if (index == 1)
        ClientManager = m_ptargetBinary;

    list <AddressRange> address_list = ClientManager->GetFunctionBasicBlocks(address);

    found_match_number = 0;
    not_found_match_number = 0;
    found_match_with_difference_number = 0;
    float total_match_rate = 0;

    for (AddressRange block : address_list)
    {
        MatchMapList *pMatchMapList = GetMatchData(index, block.Start);

        for (MatchData *pMatchData : (MatchMapList)(*pMatchMapList))
        {
            if (pMatchData->MatchRate == 100)
            {
                found_match_number++;
            }
            else
            {
                int source_instruction_hash_len = 0;
                int target_instruction_hash_len = 0;

                PBasicBlock p_basic_block = m_psourceBinary->GetBasicBlock(pMatchData->Addresses[0]);
                if (p_basic_block)
                    source_instruction_hash_len = p_basic_block->InstructionHashLen;

                p_basic_block = m_ptargetBinary->GetBasicBlock(pMatchData->Addresses[1]);
                if (p_basic_block)
                    target_instruction_hash_len = p_basic_block->InstructionHashLen;

                if (debug || m_pdumpAddressChecker->IsDumpPair(pMatchData->Addresses[0], pMatchData->Addresses[1]))
                    Logger.Log(10, LOG_DIFF_MACHINE | LOG_MATCH_RATE, "%s: Function: %X Different block(%d): %X-%X (%d%%) InstructionHash Lengths (%d:%d)\n", __FUNCTION__, address, index, pMatchData->Addresses[0], pMatchData->Addresses[1], pMatchData->MatchRate, source_instruction_hash_len, target_instruction_hash_len);

                if (source_instruction_hash_len > 0 && target_instruction_hash_len > 0)
                    found_match_with_difference_number++;
            }
            total_match_rate += pMatchData->MatchRate;
        }
        pMatchMapList->FreeMatchMapList();

        PBasicBlock p_basic_block = ClientManager->GetBasicBlock(block.Start);
        if (p_basic_block && p_basic_block->InstructionHashLen > 0)
        {
            if (debug)
                Logger.Log(10, LOG_DIFF_MACHINE | LOG_MATCH_RATE, "%s: Function: %X Non-matched block(%d): %X (instruction_hash length: %d)\n", __FUNCTION__, address, index, block.Start, p_basic_block->InstructionHashLen);

            not_found_match_number++;
        }
    }

    match_rate = total_match_rate / (found_match_number + found_match_with_difference_number + not_found_match_number);
}

BOOL DiffLogic::IsInUnidentifiedBlockHash(int index, va_t address)
{
    if (index == 0)
        return m_sourceUnidentifedBlockHash.find(address) != m_sourceUnidentifedBlockHash.end();
    else
        return m_targetUnidentifedBlockHash.find(address) != m_targetUnidentifedBlockHash.end();
}

int DiffLogic::GetUnidentifiedBlockCount(int index)
{
    if (index == 0)
        return m_sourceUnidentifedBlockHash.size();
    else
        return m_targetUnidentifedBlockHash.size();
}

AddressRange DiffLogic::GetUnidentifiedBlock(int index, int i)
{
    /*
    if( index==0 )
        return m_sourceUnidentifedBlockHash.at( i );
    else
        return m_targetUnidentifedBlockHash.at( i );
        */

    AddressRange x;
    memset(&x, 0, sizeof(x));
    return x;
}

va_t DiffLogic::DumpFunctionMatchInfo(int index, va_t address)
{
    va_t block_address = address;

    /*
    if( index==0 )
        block_address = m_psourceBinary->GetBasicBlockStart( address );
    else
        block_address = m_ptargetBinary->GetBasicBlockStart( address );
    */

    multimap <va_t, MatchData>::iterator matchMapIterator;
    if (index == 0)
    {
        m_psourceBinary->DumpBlockInfo(block_address);
        matchMapIterator = m_pMatchResults->MatchMap.find(block_address);
        while (matchMapIterator != m_pMatchResults->MatchMap.end() &&
            matchMapIterator->first == block_address)
        {
            //TODO: DumpMatchMapIterInfo("", matchMapIterator);
            m_ptargetBinary->DumpBlockInfo(matchMapIterator->second.Addresses[1]);
            matchMapIterator++;
        }
    }
    else
    {
        m_ptargetBinary->DumpBlockInfo(block_address);
        multimap <va_t, va_t>::iterator reverse_matchMapIteratorator;
        reverse_matchMapIteratorator = m_pMatchResults->ReverseAddressMap.find(block_address);
        if (reverse_matchMapIteratorator != m_pMatchResults->ReverseAddressMap.end())
        {
            //DumpMatchMapIterInfo( "", matchMapIterator );
            //TheSource->DumpBlockInfo( matchMapIterator->second.Addresses[1] );
            matchMapIterator++;
        }
    }

    return 0L;
}

void DiffLogic::RemoveMatchData(va_t sourceAddress, va_t targetAddress)
{
    for (multimap <va_t, MatchData>::iterator it = m_pMatchResults->MatchMap.find(sourceAddress);
        it != m_pMatchResults->MatchMap.end() && it->first == sourceAddress;
        it++
        )
    {
        if (it->second.Addresses[1] != targetAddress)
            continue;

        it = m_pMatchResults->MatchMap.erase(it);
    }

    for (multimap <va_t, va_t>::iterator it = m_pMatchResults->ReverseAddressMap.find(targetAddress);
        it != m_pMatchResults->ReverseAddressMap.end() && it->first == targetAddress;
        it++)
    {
        if (it->second != sourceAddress)
            continue;

        it = m_pMatchResults->ReverseAddressMap.erase(it);
    }
}

MatchMapList *DiffLogic::GetMatchData(int index, va_t address, BOOL erase)
{
    MatchMapList *pMatchMapList = NULL;

    if(m_pMatchResults)
    {
        pMatchMapList = m_pMatchResults->GetMatchData(index, address, erase);
    }
    else if (m_pdiffStorage)
    {
        pMatchMapList = m_pdiffStorage->ReadMatchMap(SourceID, TargetID, index, address, erase);
    }

    if (pMatchMapList)
    {
        Logger.Log(20, LOG_DIFF_MACHINE, "%s: %u 0x%X Returns %d entries\r\n", __FUNCTION__, index, address, pMatchMapList->Size());
    }
    return pMatchMapList;
}

va_t DiffLogic::GetMatchAddr(int index, va_t address)
{
    MatchMapList *pMatchMapList = GetMatchData(index, address);
    va_t matchAddress = pMatchMapList->GetAddress(index == 0 ? 1 : 0);
    pMatchMapList->FreeMatchMapList();
    return matchAddress;
}

BOOL DiffLogic::Save(DisassemblyStorage& disassemblyStorage, unordered_set <va_t>  *pTheSourceSelectedAddresses, unordered_set <va_t>  *pTheTargetSelectedAddresses)
{
    if (!m_psourceBinary || !m_ptargetBinary)
        return FALSE;

    //TODO: DeleteMatchInfo(disassemblyStorage);
    m_pdiffStorage->BeginTransaction();
    m_pdiffStorage->AddFileInfo("Source", SourceDBName.c_str(), SourceID, m_sourceFunctionAddress);
    m_pdiffStorage->AddFileInfo("Target", TargetDBName.c_str(), TargetID, m_targetFunctionAddress);

    multimap <va_t, MatchData>::iterator matchMapIterator;

    Logger.Log(10, LOG_DIFF_MACHINE, "DiffResults->MatchMap.size()=%u\n", m_pMatchResults->MatchMap.size());
    Logger.Log(10, LOG_DIFF_MACHINE, "DiffResults->MatchMap.size()=%u\n", m_pMatchResults->MatchMap.size());

    for (auto& val : m_pMatchResults->MatchMap)
    {
        if (
            pTheSourceSelectedAddresses &&
            pTheSourceSelectedAddresses->find(val.first) ==
            pTheSourceSelectedAddresses->end()
            )
        {
            continue;
        }

        Logger.Log(20, LOG_DIFF_MACHINE, "%s %X-%X: %d%%\n", __FUNCTION__,
            val.second.Addresses[0], val.second.Addresses[1], val.second.MatchRate);

        m_pdiffStorage->InsertMatchMap(
            m_psourceBinary->GetFileID(),
            m_ptargetBinary->GetFileID(),
            val.first,
            val.second.Addresses[1],
            val.second.Type,
            val.second.MatchRate);

        // val.second.SubType, //TODO:
        // val.second.Status,
        // val.second.UnpatchedParentAddress,
        // val.second.PatchedParentAddress);
    }

    Logger.Log(10, LOG_DIFF_MACHINE, "m_pFunctionMatchInfoList->Size()=%u\n", m_pFunctionMatchInfoList->Size());

    for (FunctionMatchInfo functionMatchInfo : (FunctionMatchInfoList)(*m_pFunctionMatchInfoList))
    {
        m_pdiffStorage->AddFunctionMatchInfo(m_psourceBinary->GetFileID(), m_ptargetBinary->GetFileID(), functionMatchInfo);
    }

    disassemblyStorage.EndTransaction();
    return TRUE;
}

// Use your own error codes here
#define SUCCESS                     0L
#define FAILURE_NULL_ARGUMENT       1L
#define FAILURE_API_CALL            2L
#define FAILURE_INSUFFICIENT_BUFFER 3L

DWORD GetBasePathFromPathName(const char *szPathName,
    const char *szBasePath,
    DWORD   dwBasePathSize)
{
    TCHAR   szDrive[_MAX_DRIVE] = { 0 };
    TCHAR   szDir[_MAX_DIR] = { 0 };
    TCHAR   szFname[_MAX_FNAME] = { 0 };
    TCHAR   szExt[_MAX_EXT] = { 0 };
    size_t  PathLength;
    DWORD   dwReturnCode;

    // Parameter validation
    if (szPathName == NULL || szBasePath == NULL)
    {
        return FAILURE_NULL_ARGUMENT;
    }

    // Split the path into it's components
    dwReturnCode = _tsplitpath_s(szPathName, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, szFname, _MAX_FNAME, szExt, _MAX_EXT);
    if (dwReturnCode != 0)
    {
        _ftprintf(stderr, TEXT("Error splitting path. _tsplitpath_s returned %d.\n"), dwReturnCode);
        return FAILURE_API_CALL;
    }

    // Check that the provided buffer is large enough to store the results and a terminal null character
    PathLength = _tcslen(szDrive) + _tcslen(szDir);
    if ((PathLength + sizeof(TCHAR)) > dwBasePathSize)
    {
        _ftprintf(stderr, TEXT("Insufficient buffer. Required %d. Provided: %d\n"), PathLength, dwBasePathSize);
        return FAILURE_INSUFFICIENT_BUFFER;
    }

    // Copy the szDrive and szDir into the provide buffer to form the basepath
    if ((dwReturnCode = _tcscpy_s((char*)szBasePath, dwBasePathSize, szDrive)) != 0)
    {
        _ftprintf(stderr, TEXT("Error copying string. _tcscpy_s returned %d\n"), dwReturnCode);
        return FAILURE_API_CALL;
    }
    if ((dwReturnCode = _tcscat_s((char*)szBasePath, dwBasePathSize, szDir)) != 0)
    {
        _ftprintf(stderr, TEXT("Error copying string. _tcscat_s returned %d\n"), dwReturnCode);
        return FAILURE_API_CALL;
    }
    return SUCCESS;
}

BOOL DiffLogic::Create(const char *DiffDBFilename)
{
    Logger.Log(10, LOG_DIFF_MACHINE, "%s\n", __FUNCTION__);

    m_pdiffStorage = (DiffStorage*)(new SQLiteDiffStorage(DiffDBFilename));
    FileList DiffFileList = m_pdiffStorage->ReadFileList();

    if (DiffFileList.SourceFilename.size() > 0 && DiffFileList.TargetFilename.size() > 0)
    {
        char *DiffDBBasename = (char*)malloc(strlen(DiffDBFilename) + 1);

        if (DiffDBBasename)
        {
            GetBasePathFromPathName(DiffDBFilename, DiffDBBasename, strlen(DiffDBFilename) + 1);
            char *FullSourceDBName = (char*)malloc(strlen(DiffDBBasename) + strlen(DiffFileList.SourceFilename.c_str()) + 1);

            if (FullSourceDBName)
            {
                strcpy(FullSourceDBName, DiffDBBasename);
                strcat(FullSourceDBName, DiffFileList.SourceFilename.c_str());
                SourceDBName = FullSourceDBName;
                free(FullSourceDBName);
            }

            char *FullTargetDBName = (char*)malloc(strlen(DiffDBBasename) + strlen(DiffFileList.TargetFilename.c_str()) + 1);

            if (FullTargetDBName)
            {
                strcpy(FullTargetDBName, DiffDBBasename);
                strcat(FullTargetDBName, DiffFileList.TargetFilename.c_str());
                TargetDBName = FullTargetDBName;
                free(FullTargetDBName);
            }

            free(DiffDBBasename);
        }
    }

    if (SourceDBName.size() > 0 && TargetDBName.size() > 0)
    {
        Logger.Log(10, LOG_DIFF_MACHINE, "	Loading %s\n", SourceDBName.c_str());
        m_psourceStorage = new SQLiteDisassemblyStorage(SourceDBName.c_str());

        Logger.Log(10, LOG_DIFF_MACHINE, "	Loading %s\n", TargetDBName.c_str());
        m_ptargetStorage = new SQLiteDisassemblyStorage(TargetDBName.c_str());
        SetTarget(TargetDBName.c_str(), 1, m_targetFunctionAddress);
    }

    return true;
}

BOOL DiffLogic::Load(const char *DiffDBFilename)
{
    Logger.Log(10, LOG_DIFF_MACHINE, "Loading %s\n", DiffDBFilename);
    Create(DiffDBFilename);

    return _Load();
}

BOOL DiffLogic::Load(DiffStorage *p_diffStorage, DisassemblyStorage  *p_disassemblyStorage)
{
    m_pdiffStorage = p_diffStorage;
    m_psourceStorage = p_disassemblyStorage;
    m_ptargetStorage = p_disassemblyStorage;

    return _Load();
}

BOOL DiffLogic::_Load()
{
    Logger.Log(10, LOG_DIFF_MACHINE, "%s\n", __FUNCTION__);

    if (m_psourceBinary)
    {
        delete m_psourceBinary;
        m_psourceBinary = NULL;
    }

    m_psourceBinary = new Binary(m_psourceStorage);

    Logger.Log(10, LOG_DIFF_MACHINE, "m_sourceFunctionAddress: %X\n", m_sourceFunctionAddress);
    m_psourceBinary->Open(SourceID);

    if (m_bloadMaps)
    {
        m_psourceBinary->FixFunctionAddresses();
        m_psourceBinary->Load(m_sourceFunctionAddress);
    }

    if (m_ptargetBinary)
    {
        delete m_ptargetBinary;
        m_ptargetBinary = NULL;
    }

    m_ptargetBinary = new Binary(m_ptargetStorage);
    m_ptargetBinary->Open(TargetID);

    if (m_bloadMaps)
    {
        m_ptargetBinary->FixFunctionAddresses();
        m_ptargetBinary->Load(m_targetFunctionAddress);
    }

    if (LoadMatchResults)
    {
        m_pMatchResults = m_pdiffStorage->ReadMatchResults(SourceID, TargetID);
    }

    return TRUE;
}

BREAKPOINTS DiffLogic::ShowUnidentifiedAndModifiedBlocks()
{
    BREAKPOINTS breakpoints;

    for (auto& val : (FunctionMatchInfoList)(*m_pFunctionMatchInfoList))
    {
        if (
            (
                val.MatchCountWithModificationForTheSource > 0 ||
                val.MatchCountWithModificationForTheTarget > 0 ||
                val.MatchRate < 100 ||
                val.NoneMatchCountForTheSource > 0 ||
                val.NoneMatchCountForTheTarget > 0
            ) &&
            val.MatchRate > 0
        )
        {

            bool found_source_blocks = false;

            for (auto& val : m_psourceBinary->GetFunctionBasicBlocks(val.SourceAddress))
            {
                multimap <va_t, MatchData>::iterator matchMapIterator = m_pMatchResults->MatchMap.find(val.Start);

                if (matchMapIterator != m_pMatchResults->MatchMap.end())
                {
                    Logger.Log(10, LOG_DIFF_MACHINE, "Unmatched: %X", val.Start);

                    if (breakpoints.SourceAddressMap.find(val.Start) == breakpoints.SourceAddressMap.end())
                        breakpoints.SourceAddressMap.insert(val.Start);

                    found_source_blocks = true;
                }
                else
                {
                    while (matchMapIterator != m_pMatchResults->MatchMap.end() && (*matchMapIterator).first != val.Start)
                    {
                        if ((*matchMapIterator).second.MatchRate < 100)
                        {
                            Logger.Log(10, LOG_DIFF_MACHINE, "Modified: %X", (*matchMapIterator).first);

                            if (breakpoints.SourceAddressMap.find(val.Start) == breakpoints.SourceAddressMap.end())
                                breakpoints.SourceAddressMap.insert(val.Start);

                            found_source_blocks = true;
                        }
                        matchMapIterator++;
                    }
                }
            }

            if (found_source_blocks)
            {
                if (breakpoints.SourceFunctionMap.find(val.TargetAddress) == breakpoints.SourceFunctionMap.end())
                    breakpoints.SourceFunctionMap.insert(val.TargetAddress);
            }

            //Target
            bool found_target_blocks = false;

            for (auto& val : m_ptargetBinary->GetFunctionBasicBlocks(val.TargetAddress))
            {
                multimap <va_t, va_t>::iterator reverse_matchMapIterator = m_pMatchResults->ReverseAddressMap.find(val.Start);

                if (reverse_matchMapIterator == m_pMatchResults->ReverseAddressMap.end())
                {
                    Logger.Log(10, LOG_DIFF_MACHINE, "Unmatched: %X", val.Start);

                    if (breakpoints.TargetAddressMap.find(val.Start) == breakpoints.TargetAddressMap.end())
                        breakpoints.TargetAddressMap.insert(val.Start);

                    found_target_blocks = true;
                }
                else
                {
                    for (; reverse_matchMapIterator != m_pMatchResults->ReverseAddressMap.end() && reverse_matchMapIterator->first == val.Start; reverse_matchMapIterator++)
                    {
                        multimap <va_t, MatchData>::iterator matchMapIterator = m_pMatchResults->MatchMap.find(reverse_matchMapIterator->second);

                        while (matchMapIterator != m_pMatchResults->MatchMap.end() && (*matchMapIterator).first != reverse_matchMapIterator->second)
                        {
                            if ((*matchMapIterator).second.MatchRate < 100)
                            {
                                Logger.Log(10, LOG_DIFF_MACHINE, "Modified: %X", (*matchMapIterator).first);

                                if (breakpoints.TargetAddressMap.find(val.Start) == breakpoints.TargetAddressMap.end())
                                    breakpoints.TargetAddressMap.insert(val.Start);
                                found_target_blocks = true;
                            }
                            matchMapIterator++;
                        }
                    }
                }
            }

            if (found_target_blocks)
            {
                if (breakpoints.TargetFunctionMap.find(val.TargetAddress) == breakpoints.TargetFunctionMap.end())
                    breakpoints.TargetFunctionMap.insert(val.TargetAddress);
            }
        }
    }
    return breakpoints;
}


void DiffLogic::PrintMatchControlFlow()
{
	multimap <va_t, MatchData>::iterator matchMapIterator;
	int unique_match_count = 0;

    for (auto& val : m_pMatchResults->MatchMap)
	{
		if (m_pMatchResults->MatchMap.count(val.first) == 1)
			unique_match_count++;
	}

	LogMessage(0, __FUNCTION__, "unique_match_count=%u\n", unique_match_count);

	//Print Summary
	//TODO: DiffResults->MatchMap -> save to database...

    for (auto& val : m_pMatchResults->MatchMap)
	{
		LogMessage(0, __FUNCTION__, "%X-%X ( %s )\n", val.first, val.second.Addresses[1], m_pdiffAlgorithms->GetMatchTypeStr(val.second.Type));
	}

	LogMessage(0, __FUNCTION__, "* *unidentified( 0 )\n");

	int unpatched_unidentified_number = 0;
	multimap <va_t, unsigned char*>::iterator source_instructionHashMap_Iter;

    for (auto& val : m_psourceBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap)
	{
		if (m_pMatchResults->MatchMap.find(val.first) == m_pMatchResults->MatchMap.end())
		{
			LogMessage(0, __FUNCTION__, "%X ", val.first);

			if (unpatched_unidentified_number % 8 == 7)
				LogMessage(0, __FUNCTION__, "\n");
			unpatched_unidentified_number++;
		}
	}
	//TODO: LogMessage(0, __FUNCTION__, unpatched_unidentified_number=%u\n", unpatched_unidentified_number);
	LogMessage(0, __FUNCTION__, "* *unidentified( 1 )\n");

	int patched_unidentified_number = 0;

    for (auto& val : m_ptargetBinary->GetClientDisassemblyHashMaps()->addressToInstructionHashMap)
	{
		if (m_pMatchResults->ReverseAddressMap.find(val.first) == m_pMatchResults->ReverseAddressMap.end())
		{
			LogMessage(0, __FUNCTION__, "%X ", val.first);
			if (patched_unidentified_number % 8 == 7)
				LogMessage(0, __FUNCTION__, "\n");
			patched_unidentified_number++;
		}
	}
	LogMessage(0, __FUNCTION__, "patched_unidentified_number=%u\n", patched_unidentified_number);
}
