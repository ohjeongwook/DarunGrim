#include "DiffMachine.h"
#include <string>
#include <list>
#include <hash_set>
#include <hash_map>
#include <stdlib.h>
#include <tchar.h>

#include "Diff.h"

#define strtoul10( X ) strtoul( X, NULL, 10 )

#define DEBUG_LEVEL 2

using namespace std;
using namespace stdext;
#include "Configuration.h"

char *MatchDataTypeStr[] = { "Name", "Fingerprint", "Two Level Fingerprint", "IsoMorphic Match", "Fingerprint Inside Function", "Function" };

#include "sqlite3.h"

extern LogOperation Logger;

class AnalysisResult
{
public:
	MATCHMAP MatchMap;
	multimap <DWORD, DWORD> ReverseAddressMap;
	DumpAddressChecker *pDumpAddressChecker;
public:
	AnalysisResult() :pDumpAddressChecker(NULL)
	{
	}

	void SetDumpAddressChecker(DumpAddressChecker *p_dump_address_checker)
	{
		pDumpAddressChecker = p_dump_address_checker;
	}

	void Clear()
	{
		MatchMap.clear();
		ReverseAddressMap.clear();
	}

	void EraseSource(vector <DWORD> &addresses, DWORD address, DWORD source, DWORD target)
	{
		for (multimap <DWORD, MatchData>::iterator it = MatchMap.find(address); it != MatchMap.end() && it->first==address; it++)
		{
			if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(it->first, it->second.Addresses[1]))
			{
				Logger.Log(10, LOG_DIFF_MACHINE, "%s %X-%X\n", __FUNCTION__, it->first, it->second.Addresses[1]);
				Logger.Log(10, LOG_DIFF_MACHINE, "\tOriginal erase target: %X-%X\n", source, target);
			}
			addresses.push_back(it->second.Addresses[1]);
			it = MatchMap.erase(it);
		}
	}

	void EraseTarget(vector <DWORD> &addresses, DWORD address, DWORD source, DWORD target)
	{
		for (multimap <DWORD, DWORD>::iterator it = ReverseAddressMap.find(address); it != ReverseAddressMap.end() && it->first==address; it++)
		{
			if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(it->second, it->first))
			{
				Logger.Log(10, LOG_DIFF_MACHINE, "%s %X-%X\n", __FUNCTION__, it->second, it->first);
				Logger.Log(10, LOG_DIFF_MACHINE, "\tOriginal erase target: %X-%X\n", source, target);
			}
			addresses.push_back(it->second);
			it = ReverseAddressMap.erase(it);
		}
	}

	void Erase(DWORD source, DWORD target)
	{
		if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(source, target))
			Logger.Log(10, LOG_DIFF_MACHINE, "%s -> %X-%X\n", __FUNCTION__, source, target);

		vector <DWORD> sources;
		vector <DWORD> targets;

		sources.push_back(source);
		targets.push_back(target);

		while (sources.size()>0)
		{
			for (vector<DWORD>::iterator it=sources.begin(); it != sources.end(); it++)
			{
				EraseSource(targets, *it, source, target );
			}
			sources.clear();

			for (vector <DWORD>::iterator it = targets.begin(); it != targets.end(); it++)
			{
				EraseTarget(sources, *it, source, target);
			}
			targets.clear();
		}
	}

	multimap <DWORD, MatchData>::iterator Erase(multimap <DWORD, MatchData>::iterator match_map_iter)
	{
		if (match_map_iter != MatchMap.end())
		{
			if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1]))
				Logger.Log(10, LOG_DIFF_MACHINE, "%s %X-%X\n", __FUNCTION__, match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1]);

			for (
				multimap <DWORD, DWORD>::iterator it = ReverseAddressMap.find(match_map_iter->second.Addresses[1]);
				it != ReverseAddressMap.end() && it->first == match_map_iter->second.Addresses[1]; 
				it++)
			{
				if (it->second == match_map_iter->first)
					it=ReverseAddressMap.erase(it);
			}
			match_map_iter=MatchMap.erase(match_map_iter);
		}
		return match_map_iter;
	}

	void AddMatchData(MatchData &match_data, char *debug_str)
	{
		if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
			Logger.Log(10, LOG_DIFF_MACHINE, "%s %s [%d] %X-%X: %d%%\n", __FUNCTION__, debug_str, match_data.Type, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

		DWORD src = match_data.Addresses[0];
		DWORD target = match_data.Addresses[1];
		bool add = true;
		for (multimap <DWORD, MatchData>::iterator it = MatchMap.find(src); it != MatchMap.end() && it->first == src; it++)
		{
			if ((*it).second.MatchRate < match_data.MatchRate)
			{
				//choose new one and erase old one
				it = MatchMap.erase(it);
				if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
					Logger.Log(10, LOG_DIFF_MACHINE, "\tErase old match %X-%X: %d%%\n", (*it).second.Addresses[0], (*it).second.Addresses[1], (*it).second.MatchRate);
			}
			else
			{
				//keep old one, don't add this
				add = false;
				if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
					Logger.Log(10, LOG_DIFF_MACHINE, "\tKeep old match %X-%X: %d%%\n", (*it).second.Addresses[0], (*it).second.Addresses[1], (*it).second.MatchRate);
			}
		}

		for (multimap<DWORD, DWORD>::iterator it = ReverseAddressMap.find(target); it != ReverseAddressMap.end() && it->first == target; it++)
		{
			for (multimap <DWORD, MatchData>::iterator it2 = MatchMap.find(it->second); it2 != MatchMap.end() && it2->first == it->second; it2++)
			{
				if ((*it2).second.MatchRate < match_data.MatchRate)
				{
					//choose new one and erase old one
					it2 = MatchMap.erase(it2);
					if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
						Logger.Log(10, LOG_DIFF_MACHINE, "\tErase old match %X-%X: %d%%\n", (*it2).second.Addresses[0], (*it2).second.Addresses[1], (*it2).second.MatchRate);
				}
				else
				{
					//keep old one, don't add this
					add = false;
					if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
						Logger.Log(10, LOG_DIFF_MACHINE, "\tKeep old match %X-%X: %d%%\n", (*it2).second.Addresses[0], (*it2).second.Addresses[1], (*it2).second.MatchRate);

				}
			}
		}

		if (add)
		{
			MatchMap.insert(MatchMap_Pair(src, match_data));
			ReverseAddressMap.insert(pair<DWORD, DWORD>(target, src));
		}
	}

	void Append(MATCHMAP *pTemporaryMap)
	{
		multimap <DWORD, MatchData>::iterator match_map_iter;
		for (match_map_iter = pTemporaryMap->begin();
			match_map_iter != pTemporaryMap->end();
			match_map_iter++)
		{
			AddMatchData(match_map_iter->second, __FUNCTION__);
		}
	}

	void CleanUp()
	{
		multimap <DWORD, MatchData>::iterator match_map_iter;
		for (match_map_iter = MatchMap.begin();
			match_map_iter != MatchMap.end();
			)
		{
			if (match_map_iter->second.Status&STATUS_MAPPING_DISABLED)
			{
				multimap <DWORD, MatchData>::iterator current_map_iter = match_map_iter;
				match_map_iter++;

				if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(current_map_iter->second.Addresses[0], current_map_iter->second.Addresses[1]))
					Logger.Log(10, LOG_DIFF_MACHINE, "%s Erase (CleanUp) %X-%X\n", __FUNCTION__, current_map_iter->second.Addresses[0], current_map_iter->second.Addresses[1]);

				for (multimap <DWORD, DWORD>::iterator reverse_match_map_iter = ReverseAddressMap.find(current_map_iter->second.Addresses[1]); 
					reverse_match_map_iter != ReverseAddressMap.end() && reverse_match_map_iter->first == current_map_iter->second.Addresses[1];
					reverse_match_map_iter++)
				{
					reverse_match_map_iter=ReverseAddressMap.erase(reverse_match_map_iter);
				}

				MatchMap.erase(current_map_iter);

				continue;
			}
			match_map_iter++;
		}
	}
};


DiffMachine::DiffMachine( IDAController *the_source, IDAController *the_target ):
	DebugFlag( 0 ),
	SourceController(NULL),
	TargetController( NULL ),
	bRetrieveDataForAnalysis(FALSE),
	SourceID(0),
	SourceFunctionAddress(0),
	TargetID(0),
	TargetFunctionAddress(0),
	LoadIDAController(false),
	LoadDiffResults(true),
	ShowFullMatched(false),
	ShowNonMatched(false),
	pDumpAddressChecker(NULL)
{
	m_DiffDB=NULL;
	DiffResults=NULL;
	SetSource(the_source);
	SetTarget(the_target);
}

void DiffMachine::ClearFunctionMatchList()
{
	vector <FunctionMatchInfo>::iterator iter;
	for( iter=FunctionMatchList.begin();iter!=FunctionMatchList.end();iter++ )
	{
		free( (*iter).TheSourceFunctionName );
		free( (*iter).TheTargetFunctionName );
	}
	FunctionMatchList.clear();
}

DiffMachine::~DiffMachine()
{
	if( DiffResults )
	{
		DiffResults->Clear();
	}

	ClearFunctionMatchList();
	
	if( SourceController )
		delete SourceController;

	if( TargetController )
		delete TargetController;
}

IDAController *DiffMachine::GetSourceController()
{
	return SourceController;
}

IDAController *DiffMachine::GetTargetController()
{
	return TargetController;
}

int DiffMachine::GetFingerPrintMatchRate( unsigned char* unpatched_finger_print, unsigned char* patched_finger_print )
{
	int rate=0;
	char *unpatched_finger_print_str=BytesWithLengthAmbleToHex( unpatched_finger_print );
	if( unpatched_finger_print_str )
	{
		char *patched_finger_print_str=BytesWithLengthAmbleToHex( patched_finger_print );
		if( patched_finger_print_str )
		{
			int unpatched_finger_print_str_len = strlen(unpatched_finger_print_str);
			int patched_finger_print_str_len = strlen(patched_finger_print_str);
			int diff_len = (unpatched_finger_print_str_len - patched_finger_print_str_len);
			if (diff_len > unpatched_finger_print_str_len*0.5 || diff_len > patched_finger_print_str_len*0.5)
			{
				rate = 0;
			}
			else
			{
				rate = GetStringSimilarity(unpatched_finger_print_str, patched_finger_print_str);
			}
			free( unpatched_finger_print_str );
		}
		free( patched_finger_print_str );
	}
	return rate;
}

int DiffMachine::GetMatchRate( DWORD unpatched_address, DWORD patched_address )
{
	multimap <DWORD,  unsigned char *>::iterator source_fingerprint_hash_map_Iter;
	multimap <DWORD,  unsigned char *>::iterator target_fingerprint_hash_map_Iter;
						
	source_fingerprint_hash_map_Iter=SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find( unpatched_address );
	target_fingerprint_hash_map_Iter=TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find( patched_address );

	if( 
		source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
		target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end()
	 )
	{
		return GetFingerPrintMatchRate( 
			source_fingerprint_hash_map_Iter->second, 
			target_fingerprint_hash_map_Iter->second );
	}
	return 0;
}

void DiffMachine::DumpMatchMapIterInfo( const char *prefix, multimap <DWORD,  MatchData>::iterator match_map_iter )
{
	char *SubTypeStr[]={"Cref From", "Cref To", "Call", "Dref From", "Dref To"};	

	Logger.Log( 11, LOG_DIFF_MACHINE, "%s: match: %X - %X ( %s/%s ) from: %X %X ( Match rate=%u/100 ) Status=%X\n", 
			prefix, 
			match_map_iter->first, 
			match_map_iter->second.Addresses[1], 
			MatchDataTypeStr[match_map_iter->second.Type], 
			( match_map_iter->second.Type==TREE_MATCH && match_map_iter->second.SubType<sizeof( SubTypeStr )/sizeof( char * ) )?SubTypeStr[match_map_iter->second.SubType]:"None", 
			match_map_iter->second.UnpatchedParentAddress, 
			match_map_iter->second.PatchedParentAddress, 
			match_map_iter->second.MatchRate, 
			match_map_iter->second.Status );
}

void DiffMachine::AnalyzeFunctionSanity()
{
	multimap <DWORD,  MatchData>::iterator last_match_map_iter;
	multimap <DWORD,  MatchData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	DWORD unpatched_addr=0;
	DWORD patched_addr=0;

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: DiffResults->MatchMap Size=%u\n", __FUNCTION__, DiffResults->MatchMap.size() );	
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
#ifdef USE_LEGACY_MAP
		multimap <DWORD,  PBasicBlock>::iterator address_hash_map_pIter;
		address_hash_map_pIter = SourceController->GetClientAnalysisInfo()->address_hash_map.find( match_map_iter->first );
		if( address_hash_map_pIter != SourceController->GetClientAnalysisInfo()->address_hash_map.end() )
		{
			PBasicBlock p_basic_block=address_hash_map_pIter->second;
#else
		PBasicBlock p_basic_block = SourceController->GetBasicBlock(match_map_iter->first);
		if( p_basic_block )
		{
#endif
			unpatched_addr=match_map_iter->first;
			patched_addr=match_map_iter->second.Addresses[1];
			if( last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr
			 )
			{
				if( p_basic_block->BlockType==FUNCTION_BLOCK )
				{
				}else
				{
				}
			}
			if( last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			 )
			{
				Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: **** Multiple Possibilities\n", __FUNCTION__ );
				DumpMatchMapIterInfo( "", last_match_map_iter );
				DumpMatchMapIterInfo( "", match_map_iter );
			}

			last_match_map_iter=match_map_iter;
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;
#ifndef USE_LEGACY_MAP
			free( p_basic_block );
#endif
		}
	}

	multimap <DWORD, DWORD>::iterator reverse_match_map_iterator;
	for( reverse_match_map_iterator=DiffResults->ReverseAddressMap.begin();
		reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end();
		reverse_match_map_iterator++ )
	{
#ifdef USE_LEGACY_MAP
		multimap <DWORD,  PBasicBlock>::iterator address_hash_map_pIter;
		address_hash_map_pIter = TargetController->GetClientAnalysisInfo()->address_hash_map.find( reverse_match_map_iterator->first );

		if( address_hash_map_pIter != TargetController->GetClientAnalysisInfo()->address_hash_map.end() )
		{
			PBasicBlock p_basic_block=address_hash_map_pIter->second;
#else
		PBasicBlock p_basic_block=SourceController->GetBasicBlock( reverse_match_map_iterator->first );
		if( p_basic_block )
		{			
#endif
			unpatched_addr=reverse_match_map_iterator->first;
			patched_addr=reverse_match_map_iterator->second;
			
			if( last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr )
			{
				if( p_basic_block->BlockType==FUNCTION_BLOCK )
				{
				}else
				{
				}
			}
			if( last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			 )
			{
				Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: **** Multiple Possibilities\n", __FUNCTION__ );
				//DumpMatchMapIterInfo( "", match_map_iter );
			}else
			{
			}
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;

			free( p_basic_block );
		}
	}
}

void DiffMachine::CleanUpMatchDataList(vector<MatchData *> match_data_list)
{
	for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
	{
		if (*it)
		{
			delete (*it);
		}
	}
}

void DiffMachine::TestFunctionMatchRate( int index, DWORD Address )
{
	IDAController *ClientManager=index==0?SourceController:TargetController;
	list <BLOCK> address_list = ClientManager->GetFunctionMemberBlocks(Address);
	list <BLOCK>::iterator address_list_iter;

	for( address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	 )
	{
		vector<MatchData *> match_data_list=GetMatchData(index, (*address_list_iter).Start);
		if (match_data_list.size()>0)
		{
			for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
			{
				Logger.Log(10, LOG_DIFF_MACHINE, "Basic Block: %X Match Rate: %d%%\n", (*address_list_iter).Start, (*it)->MatchRate);
			}
			CleanUpMatchDataList(match_data_list);
		}
		else
		{
			Logger.Log(10, LOG_DIFF_MACHINE, "Basic Block: %X Has No Match.\n", (*address_list_iter).Start);
		}

		CleanUpMatchDataList(match_data_list);
	}
}

void DiffMachine::RetrieveNonMatchingMembers( int index, DWORD FunctionAddress, list <DWORD>& Members )
{
	IDAController *ClientManager=index==0?SourceController:TargetController;
	list <BLOCK> address_list=ClientManager->GetFunctionMemberBlocks( FunctionAddress );

	for( list <BLOCK>::iterator address_list_iter = address_list.begin();
		address_list_iter != address_list.end();
		address_list_iter++
	 )
	{

		vector<MatchData *> match_data_list = GetMatchData(index, (*address_list_iter).Start);
		if (match_data_list.size()>0)
		{
			for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
			{
				if ((*it)->MatchRate < 100)
				{
					Members.push_back((*address_list_iter).Start);
					break;
				}
			}
			CleanUpMatchDataList(match_data_list);
		}
		else
		{
			Members.push_back((*address_list_iter).Start);
		}

		CleanUpMatchDataList(match_data_list);
	}
}

bool DiffMachine::TestAnalysis()
{
	return TRUE;
}

bool DiffMachine::DoFunctionLevelMatchOptimizing()
{
	if (DebugFlag  & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING)
		Logger.Log(10, LOG_DIFF_MACHINE, "%s: DoFunctionLevelMatchOptimizing\n", __FUNCTION__);

	vector <FunctionMatchInfo>::iterator iter;
	for( iter=FunctionMatchList.begin();iter!=FunctionMatchList.end();iter++ )
	{
		Logger.Log(11, LOG_DIFF_MACHINE,
			"Source FileID: 0x%.8x\n"
			"Target FileID: 0x%.8x\n"
			"TheSourceAddress : 0x%.8x\n"
			"EndAddress : 0x%.8x\n"
			"TheTargetAddress : 0x%.8x\n"
			"BlockType : 0x%.8x\n"
			"MatchRate : 0x%.8x\n"
			"TheSourceFunctionName : %s\n"
			"Type : 0x%.8x\n"
			"TheTargetFunctionName : %s\n"
			"MatchCountForTheSource : 0x%.8x\n"
			"NoneMatchCountForTheSource : 0x%.8x\n"
			"MatchCountWithModificationForTheSource : 0x%.8x\n"
			"MatchCountForTheTarget : 0x%.8x\n"
			"NoneMatchCountForTheTarget : 0x%.8x\n"
			"MatchCountWithModificationForTheTarget: 0x%.8x\n"
			"\r\n",
			SourceController->GetFileID(),
			TargetController->GetFileID(),
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
		if( DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING )
		{
			Logger.Log( 10, LOG_DIFF_MACHINE,  "** Unpatched:\n" );
			TestFunctionMatchRate( 0, iter->TheSourceAddress );

			Logger.Log( 10, LOG_DIFF_MACHINE,  "** Patched:\n" );
			TestFunctionMatchRate( 1, iter->TheTargetAddress );
		}

		list <DWORD> SourceMembers;
		RetrieveNonMatchingMembers( 0, iter->TheSourceAddress, SourceMembers );

		list <DWORD> TargetMembers;
		RetrieveNonMatchingMembers( 1, iter->TheTargetAddress, TargetMembers );


		if( DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING )
		{
			Logger.Log( 10, LOG_DIFF_MACHINE,  "Source Members\n" );
			for( list <DWORD>::iterator member_iter = SourceMembers.begin();
				member_iter != SourceMembers.end();
				member_iter++
			 )
			{
				Logger.Log( 10, LOG_DIFF_MACHINE, "0x%X, ", *member_iter );
			}
			Logger.Log( 10, LOG_DIFF_MACHINE,  "\n" );

			Logger.Log( 10, LOG_DIFF_MACHINE,  "Target Members\n" );
			for( list <DWORD>::iterator member_iter = TargetMembers.begin();
				member_iter != TargetMembers.end();
				member_iter++
			 )
			{
				Logger.Log( 10, LOG_DIFF_MACHINE, "0x%X, ", *member_iter );
			}
			Logger.Log( 10, LOG_DIFF_MACHINE,  "\n" );
		}

		for( list <DWORD>::iterator source_member_iter = SourceMembers.begin();
			source_member_iter != SourceMembers.end();
			source_member_iter++
		 )
		{
			for( list <DWORD>::iterator target_member_iter = TargetMembers.begin();
				target_member_iter != TargetMembers.end();
				target_member_iter++
			 )
			{
				bool debug = false;

				if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(*source_member_iter, *target_member_iter))
					debug = true;

				int current_match_rate=GetMatchRate( *source_member_iter, *target_member_iter );

				if (debug)
					Logger.Log( 10, LOG_DIFF_MACHINE, "%s: Try to insert %X-%X: %d%%\n", __FUNCTION__, *source_member_iter, *target_member_iter, current_match_rate );

				bool add_current_entry = true;

				//Remove any existing entries with smaller match rate than current one
				vector<MatchData *> match_data_list = GetMatchData(0, *source_member_iter);
				if (match_data_list.size()>0)
				{
					add_current_entry = false;
					for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
					{
						char *operation = "Retain";
						if ((*it)->MatchRate < current_match_rate)
						{
							RemoveMatchData((*it)->Addresses[0], (*it)->Addresses[1]);
							add_current_entry = true;
							if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair((*it)->Addresses[0], (*it)->Addresses[1]))
								debug = true;
							operation = "Remove";
						}

						if (debug)
							Logger.Log(10, LOG_DIFF_MACHINE, "\t%s %X-%X: %d%%\n", operation, *source_member_iter, (*it)->Addresses[1], (*it)->MatchRate);
					}
					CleanUpMatchDataList(match_data_list);
				}

				CleanUpMatchDataList(match_data_list);

				match_data_list = GetMatchData(1, *target_member_iter);
				if (match_data_list.size()>0)
				{
					add_current_entry = false;
					for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
					{
						char *operation = "Retain";
						if ((*it)->MatchRate < current_match_rate)
						{
							RemoveMatchData((*it)->Addresses[0], (*it)->Addresses[1]);
							add_current_entry = true;
							if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair((*it)->Addresses[0], (*it)->Addresses[1]))
								debug = true;
							operation = "Remove";
						}
						if (debug)
							Logger.Log(10, LOG_DIFF_MACHINE, "\t%s %X-%X: %d%%\n", operation, (*it)->Addresses[0], *target_member_iter, (*it)->MatchRate);
					}
					CleanUpMatchDataList(match_data_list);
				}

				if (add_current_entry)
				{
					if (debug)
					{
						Logger.Log(10, LOG_DIFF_MACHINE, "* Replacing existing match data entries...\n");
						Logger.Log(10, LOG_DIFF_MACHINE, "\t%X-%X: %d%%\n", *source_member_iter, *target_member_iter, current_match_rate);
					}

					if( DiffResults )
					{
						MatchData match_data;
						memset( &match_data, 0, sizeof( MatchData ) );
						match_data.Type=FINGERPRINT_INSIDE_FUNCTION_MATCH;
						match_data.SubType = 0;
						match_data.Addresses[0] = *source_member_iter;
						match_data.Addresses[1] = *target_member_iter;

						match_data.UnpatchedParentAddress=0;
						match_data.PatchedParentAddress=0;
						match_data.MatchRate = current_match_rate;

						DiffResults->Erase(*source_member_iter, *target_member_iter);
						DiffResults->AddMatchData(match_data, __FUNCTION__);
					}
					else
					{
						m_DiffDB->ExecuteStatement( NULL, NULL, INSERT_MATCH_MAP_TABLE_STATEMENT, 
							SourceController->GetFileID(), 
							TargetController->GetFileID(), 
							*source_member_iter,
							*target_member_iter,
							TYPE_MATCH,
							FINGERPRINT_INSIDE_FUNCTION_MATCH,
							0,
							0,
							current_match_rate,
							0,
							0 );
					}
				}
			}
		}

	}
	return TRUE;
}

void DumpAddressChecker::AddSrcDumpAddress(DWORD address)
{
	SrcDumpAddresses.insert(address);
}

void DumpAddressChecker::AddTargetDumpAddress(DWORD address)
{
	TargetDumpAddresses.insert(address);
}

bool DumpAddressChecker::IsDumpPair(DWORD src, DWORD target)
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

void DumpAddressChecker::DumpMatchInfo(DWORD src, DWORD target, int match_rate, const char *format, ...)
{
	if (IsDumpPair(src, target))
	{
		Logger.Log(10, LOG_DIFF_MACHINE, format);
		Logger.Log(10, LOG_DIFF_MACHINE, "\t%X %X (%d%%)\n", src, target, match_rate);
	}
}

bool DiffMachine::Analyze()
{
	multimap <DWORD,  PBasicBlock>::iterator address_hash_map_pIter;
	multimap <string,  DWORD>::iterator fingerprint_hash_map_pIter;
	multimap <string,  DWORD>::iterator name_hash_map_pIter;
	multimap <DWORD,  PMapInfo>::iterator map_info_hash_map_pIter;
	MATCHMAP TemporaryMatchMap;

	if (!SourceController || !TargetController)
		return FALSE;

	SourceController->LoadBasicBlock();
	TargetController->LoadBasicBlock();

	DiffResults=new AnalysisResult;
	DiffResults->SetDumpAddressChecker(pDumpAddressChecker);

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Fingerprint Map Size %u:%u\n", __FUNCTION__, 
		SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.size(), 
		TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.size() );

	// Name Match
	Logger.Log(10, LOG_DIFF_MACHINE, "Name Match\n");

	multimap <string,  DWORD>::iterator patched_name_hash_map_pIter;

	for (name_hash_map_pIter = SourceController->GetClientAnalysisInfo()->name_hash_map.begin();
		name_hash_map_pIter != SourceController->GetClientAnalysisInfo()->name_hash_map.end();
		name_hash_map_pIter++ )
	{
		if (SourceController->GetClientAnalysisInfo()->name_hash_map.count(name_hash_map_pIter->first) == 1)
		{
			//unique key
			if (TargetController->GetClientAnalysisInfo()->name_hash_map.count(name_hash_map_pIter->first) == 1)
			{
				if( name_hash_map_pIter->first.find( "loc_" )!=string::npos || 
					name_hash_map_pIter->first.find( "locret_" )!=string::npos ||
					name_hash_map_pIter->first.find( "sub_" )!=string::npos ||
					name_hash_map_pIter->first.find( "func_" )!=string::npos )
					continue;

				patched_name_hash_map_pIter = TargetController->GetClientAnalysisInfo()->name_hash_map.find( name_hash_map_pIter->first );

				if( patched_name_hash_map_pIter != TargetController->GetClientAnalysisInfo()->name_hash_map.end() )
				{
					MatchData match_data;
					memset( &match_data, 0, sizeof( MatchData ) );
					match_data.Type=NAME_MATCH;
					match_data.Addresses[0]=name_hash_map_pIter->second;
					match_data.Addresses[1]=patched_name_hash_map_pIter->second;
					match_data.MatchRate=GetMatchRate( 
						name_hash_map_pIter->second, 
						patched_name_hash_map_pIter->second
						 );

					if (pDumpAddressChecker)
						pDumpAddressChecker->DumpMatchInfo(match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate, "%s Add to temporary match map", __FUNCTION__ );

					TemporaryMatchMap.insert( MatchMap_Pair( 
						name_hash_map_pIter->second, 
						match_data
						 ) );
				}
			}
		}
	}
	Logger.Log(10, LOG_DIFF_MACHINE, "Name Match Ended\n");

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Name matched number=%u\n", __FUNCTION__, TemporaryMatchMap.size() );

	int OldMatchMapSize=0;
	while( 1 )
	{
		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: DoFingerPrintMatch\n", __FUNCTION__ );

		DoFingerPrintMatch( &TemporaryMatchMap );
		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Match Map Size: %u\n", __FUNCTION__, TemporaryMatchMap.size() );

		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: DoIsomorphMatch\n", __FUNCTION__ );

		DoIsomorphMatch( &TemporaryMatchMap );

		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Match Map Size: %u\n", __FUNCTION__, TemporaryMatchMap.size() );

		if( TemporaryMatchMap.size()>0 )
		{
			DiffResults->Append(&TemporaryMatchMap);
		}else
		{
			break;
		}
		PurgeFingerprintHashMap( &TemporaryMatchMap );
		TemporaryMatchMap.clear();

		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Call DoFunctionMatch\n", __FUNCTION__ );

		DoFunctionMatch( &TemporaryMatchMap );

		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: One Loop Of Analysis MatchMap size is %u.\n", __FUNCTION__, DiffResults->MatchMap.size() );

		if( OldMatchMapSize==DiffResults->MatchMap.size() )
			break;

		OldMatchMapSize=DiffResults->MatchMap.size();
	}

	RemoveDuplicates();
	//AnalyzeFunctionSanity();
	GenerateFunctionMatchInfo();
	DoFunctionLevelMatchOptimizing();
	GenerateFunctionMatchInfo();
	return true;
}

void DiffMachine::AppendToMatchMap(MATCHMAP *pBaseMap, MATCHMAP *pTemporaryMap)
{
	multimap <DWORD,  MatchData>::iterator match_map_iter;

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Appending %u Items To MatchMap\n", __FUNCTION__, pTemporaryMap->size() );
	for( match_map_iter=pTemporaryMap->begin();
		match_map_iter!=pTemporaryMap->end();
		match_map_iter++ )
	{
		pBaseMap->insert( MatchMap_Pair( match_map_iter->first, match_map_iter->second ) );
	}
}

void DiffMachine::PurgeFingerprintHashMap(MATCHMAP *pTemporaryMap)
{
	multimap <DWORD,  MatchData>::iterator match_map_iter;

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Delete %u Items from Fingerprint Map( %u-%u )\n", __FUNCTION__, pTemporaryMap->size(), 
		SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.size(), 
		TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.size() );

	for( match_map_iter=pTemporaryMap->begin();
		match_map_iter!=pTemporaryMap->end();
		match_map_iter++ )
	{
		//Remove from fingerprint hash map
		multimap <DWORD,  unsigned char *>::iterator address_fingerprint_hash_map_Iter;
		address_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(match_map_iter->second.Addresses[0]);
		if( address_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() )
		{
			SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.erase( address_fingerprint_hash_map_Iter->second );
		}
		address_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find( match_map_iter->second.Addresses[1] );
		if( address_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() )
		{
			TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.erase( address_fingerprint_hash_map_Iter->second );
		}
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: %u-%u\n", __FUNCTION__, 
		SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.size(), 
		TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.size() );
}

void DiffMachine::DoFingerPrintMatch(MATCHMAP *p_match_map)
{
	multimap <unsigned char *, DWORD, hash_compare_fingerprint>::iterator fingerprint_hash_map_pIter;
	multimap <unsigned char *,  DWORD, hash_compare_fingerprint>::iterator patched_fingerprint_hash_map_pIter;

	for (fingerprint_hash_map_pIter = SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.begin();
		fingerprint_hash_map_pIter != SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.end();
		fingerprint_hash_map_pIter++ )
	{
		if (SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.count(fingerprint_hash_map_pIter->first) == 1)
		{
			//unique key
			if( TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.count( fingerprint_hash_map_pIter->first )==1 )
			{
				patched_fingerprint_hash_map_pIter = TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.find( fingerprint_hash_map_pIter->first );
				if( patched_fingerprint_hash_map_pIter != TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.end() )
				{
					MatchData match_data;
					memset( &match_data, 0, sizeof( MatchData ) );
					match_data.Type=FINGERPRINT_MATCH;
					match_data.Addresses[0]=fingerprint_hash_map_pIter->second;
					match_data.Addresses[1]=patched_fingerprint_hash_map_pIter->second;
					match_data.MatchRate=100;

					if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
						Logger.Log(10, LOG_DIFF_MACHINE, "%s %X-%X: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

					p_match_map->insert( MatchMap_Pair( 
						fingerprint_hash_map_pIter->second, 
						match_data
						 ) );
				}
			}
		}
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Matched pair count=%u\n", __FUNCTION__, p_match_map->size() );
}

MatchRateInfo *DiffMachine::GetMatchRateInfoArray(DWORD source_address, DWORD target_address, int type, int &match_rate_info_count)
{
	int source_addresses_number;
	int target_addresses_number;
	match_rate_info_count = 0;
	bool debug = false;

	if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(source_address, target_address))
	{
		debug = true;
		Logger.Log(10, LOG_DIFF_MACHINE, "%s: %X-%X %d\n", __FUNCTION__, source_address, target_address, type);
	}

	DWORD *source_addresses = SourceController->GetMappedAddresses(source_address, type, &source_addresses_number);
	DWORD *target_addresses = TargetController->GetMappedAddresses(target_address, type, &target_addresses_number);

	if (debug)
	{
		Logger.Log(10, LOG_DIFF_MACHINE, "%s: Tree Matching Mapped Address Count: %X( %X ) %X( %X )\n", __FUNCTION__,
			source_addresses_number, source_address,
			target_addresses_number, target_address);

		int i;
		Logger.Log(10, LOG_DIFF_MACHINE, "Source Addresses:\n");
		for (i = 0; i < source_addresses_number; i++)
			Logger.Log(10, LOG_DIFF_MACHINE, "\t%X\n", source_addresses[i]);


		Logger.Log(10, LOG_DIFF_MACHINE, "Target Addresses:\n");
		for (i = 0; i < target_addresses_number; i++)
			Logger.Log(10, LOG_DIFF_MACHINE, "\t%X\n", target_addresses[i]);
	}

	if (source_addresses_number != 0 && target_addresses_number != 0)
	{
		MatchRateInfo *p_match_rate_info_array = new MatchRateInfo[source_addresses_number*target_addresses_number];

		if (source_addresses_number > 2 && source_addresses_number == target_addresses_number && type == CREF_FROM)
		{
			//Special case for switch case
			for (int i = 0; i < source_addresses_number; i++)
			{
				multimap <DWORD, unsigned char *>::iterator source_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(source_addresses[i]);
				multimap <DWORD, unsigned char *>::iterator target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(target_addresses[i]);

				if (source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
					target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
				{
					p_match_rate_info_array[match_rate_info_count].Source = source_addresses[i];
					p_match_rate_info_array[match_rate_info_count].Target = target_addresses[i];

					p_match_rate_info_array[match_rate_info_count].MatchRate = GetFingerPrintMatchRate
										(source_fingerprint_hash_map_Iter->second, 
										target_fingerprint_hash_map_Iter->second);
					p_match_rate_info_array[match_rate_info_count].IndexDiff = 0;
					if (debug)
						Logger.Log(10, LOG_DIFF_MACHINE, "\tAdding %X-%X (%d%%, IndexDiff:%d)\n", p_match_rate_info_array[match_rate_info_count].Source, p_match_rate_info_array[match_rate_info_count].Target, p_match_rate_info_array[match_rate_info_count].MatchRate, p_match_rate_info_array[match_rate_info_count].IndexDiff);
					match_rate_info_count++;
				}
			}
		}
		else
		{
			if (debug)
				Logger.Log(10, LOG_DIFF_MACHINE, "Adding matches\n");

			multimap <DWORD, DWORD> address_pair_map;
			for (int i = 0; i < source_addresses_number; i++)
			{
				multimap <DWORD, unsigned char *>::iterator source_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(source_addresses[i]);

				for (int j = 0; j < target_addresses_number; j++)
				{
					multimap <DWORD, DWORD>::iterator it = address_pair_map.find(source_addresses[i]);

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

					address_pair_map.insert(pair<DWORD, DWORD>(source_addresses[i], target_addresses[j]));

					multimap <DWORD, unsigned char *>::iterator target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(target_addresses[j]);

					if (source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
						target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
					{
						p_match_rate_info_array[match_rate_info_count].Source = source_addresses[i];
						p_match_rate_info_array[match_rate_info_count].Target = target_addresses[j];

						p_match_rate_info_array[match_rate_info_count].MatchRate = GetFingerPrintMatchRate(source_fingerprint_hash_map_Iter->second, target_fingerprint_hash_map_Iter->second);
						p_match_rate_info_array[match_rate_info_count].IndexDiff = abs(i - j);
						if (debug)
							Logger.Log(10, LOG_DIFF_MACHINE, "\tAdding %X-%X (%d%%, IndexDiff: %d)\n", p_match_rate_info_array[match_rate_info_count].Source, p_match_rate_info_array[match_rate_info_count].Target, p_match_rate_info_array[match_rate_info_count].MatchRate, p_match_rate_info_array[match_rate_info_count].IndexDiff);
						match_rate_info_count++;
					}
					else if (source_fingerprint_hash_map_Iter == SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
						target_fingerprint_hash_map_Iter == TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
					{
						p_match_rate_info_array[match_rate_info_count].Source = source_addresses[i];
						p_match_rate_info_array[match_rate_info_count].Target = target_addresses[j];
						p_match_rate_info_array[match_rate_info_count].MatchRate = 100;
						p_match_rate_info_array[match_rate_info_count].IndexDiff = abs(i - j);
						if (debug)
							Logger.Log(10, LOG_DIFF_MACHINE, "\tAdding %X-%X (%d%%, IndexDiff: %d)\n", p_match_rate_info_array[match_rate_info_count].Source, p_match_rate_info_array[match_rate_info_count].Target, p_match_rate_info_array[match_rate_info_count].MatchRate, p_match_rate_info_array[match_rate_info_count].IndexDiff);
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

void DiffMachine::DoIsomorphMatch(MATCHMAP *pOrigTemporaryMap)
{
	MATCHMAP *pTemporaryMap = pOrigTemporaryMap;
	int link_types[]={CREF_FROM, CALL, DREF_FROM}; //CREF_TO, DREF_TO

	while( pTemporaryMap->size()>0 )
	{
		int processed_count=0;
		multimap <DWORD,  MatchData>::iterator match_map_iter;
		MATCHMAP *pNewTemporaryMap = new MATCHMAP;

		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Current match count=%u\n", __FUNCTION__, pTemporaryMap->size() );

		for( match_map_iter=pTemporaryMap->begin(); match_map_iter!=pTemporaryMap->end(); match_map_iter++ )
		{
			for (int i = 0; i<sizeof(link_types) / sizeof(int); i++)
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
						&DiffResults->MatchMap,
						pOrigTemporaryMap,
						pNewTemporaryMap,
						pTemporaryMap };

					multimap <DWORD, MatchData>::iterator it;
					for (int compare_i = 0; compare_i < sizeof(p_compared_match_map) / sizeof(p_compared_match_map[0]); compare_i++)
					{
						it = p_compared_match_map[compare_i]->find(p_match_rate_info_array[selected_index].Source);

						while (it != p_compared_match_map[compare_i]->end() &&
							it->first == p_match_rate_info_array[selected_index].Source
							)
						{
							if (it->second.Addresses[1] == p_match_rate_info_array[selected_index].Target)
							{
								if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(p_match_rate_info_array[selected_index].Source, p_match_rate_info_array[selected_index].Target))
								{
									Logger.Log(10, LOG_DIFF_MACHINE, "%s Trying to add %X-%X: %d%%\n", __FUNCTION__,
										p_match_rate_info_array[selected_index].Source,
										p_match_rate_info_array[selected_index].Target,
										p_match_rate_info_array[selected_index].MatchRate);

									Logger.Log(10, LOG_DIFF_MACHINE, "\tAnother match is already there %X-%X\n",
										p_match_rate_info_array[selected_index].Source,
										p_match_rate_info_array[selected_index].Target);
								}

								add_match_map = FALSE;
								break;
							}
							else if (p_match_rate_info_array[selected_index].MatchRate <= it->second.MatchRate)
							{
								if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(p_match_rate_info_array[selected_index].Source, it->second.Addresses[1]))
								{
									Logger.Log(10, LOG_DIFF_MACHINE, "%s Trying to add %X-%X: %d%%\n", __FUNCTION__,
										p_match_rate_info_array[selected_index].Source,
										p_match_rate_info_array[selected_index].Target,
										p_match_rate_info_array[selected_index].MatchRate);
									Logger.Log(10, LOG_DIFF_MACHINE, "\tAnother match is already there with higher or equal match rate %X-%X( %u%% )\n",
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

						if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
						{
							Logger.Log(10, LOG_DIFF_MACHINE, "%s %X-%X: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);
							Logger.Log(10, LOG_DIFF_MACHINE, "\tParent %X-%X (link type: %d, match_rate_info_count:%d)\n", match_map_iter->first, match_map_iter->second.Addresses[1], link_types[i], match_rate_info_count);
						}

						pNewTemporaryMap->insert(MatchMap_Pair(
							p_match_rate_info_array[selected_index].Source,
							match_data
							));

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

			if( processed_count%100==0 || processed_count==pTemporaryMap->size() )
			{
				Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: %u/%u Items processed and produced %u match entries.\n", __FUNCTION__, 
					processed_count, 
					pTemporaryMap->size(), 
					pNewTemporaryMap->size()
				 );
			}
		}

		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: New Tree Match count=%u\n", __FUNCTION__, pNewTemporaryMap->size() );
		if( pNewTemporaryMap->size()>0 )
		{
			AppendToMatchMap( pOrigTemporaryMap, pNewTemporaryMap );
			if( pTemporaryMap!=pOrigTemporaryMap )
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

void DiffMachine::DoFunctionMatch(MATCHMAP *pTargetTemporaryMap)
{
	multimap <DWORD, DWORD> *FunctionMembersMapForTheSource;
	multimap <DWORD, DWORD> *FunctionMembersMapForTheTarget;

	SourceController->LoadBlockToFunction();
	TargetController->LoadBlockToFunction();
	FunctionMembersMapForTheSource = SourceController->GetFunctionToBlock();
	FunctionMembersMapForTheTarget = TargetController->GetFunctionToBlock();

	multimap <DWORD, DWORD>::iterator FunctionMembersIter;
	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	multimap <DWORD, DWORD>::iterator SourceFunctionMembersIter;
	DWORD SourceFunctionAddress=0;
	list <DWORD> SourceBlockAddresses;
	for( SourceFunctionMembersIter=FunctionMembersMapForTheSource->begin();;SourceFunctionMembersIter++ )
	{
		if( SourceFunctionMembersIter==FunctionMembersMapForTheSource->end() || SourceFunctionAddress!=SourceFunctionMembersIter->first )
		{
			//SourceFunctionAddress, SourceBlockAddresses
			hash_set <DWORD> TargetFunctionAddresses;
			for (multimap <DWORD, MatchData>::iterator MatchMapIter = DiffResults->MatchMap.find(SourceFunctionAddress); 
				MatchMapIter != DiffResults->MatchMap.end() && MatchMapIter->first == SourceFunctionAddress;
				MatchMapIter++)
			{
				//TargetFunctionAddress, TargetBlockAddresses
				DWORD TargetFunctionAddress=MatchMapIter->second.Addresses[1];
				if( TargetFunctionAddresses.find( TargetFunctionAddress )==TargetFunctionAddresses.end() )
					continue;

				TargetFunctionAddresses.insert( TargetFunctionAddress );
				multimap <DWORD, DWORD>::iterator TargetFunctionMembersIter;
				list <DWORD> TargetBlockAddresses;
				for( TargetFunctionMembersIter=FunctionMembersMapForTheTarget->find( TargetFunctionAddress );
					TargetFunctionMembersIter!=FunctionMembersMapForTheTarget->end() &&
					TargetFunctionMembersIter->first==TargetFunctionAddress;
					TargetFunctionMembersIter++ )
				{
					TargetBlockAddresses.push_back( TargetFunctionMembersIter->second );
				}
				//, 
				DoFingerPrintMatchInsideFunction(SourceFunctionAddress, SourceBlockAddresses, TargetFunctionAddress, TargetBlockAddresses);
				TargetBlockAddresses.clear();
			}
			TargetFunctionAddresses.clear();
			SourceBlockAddresses.clear();
			if( SourceFunctionMembersIter==FunctionMembersMapForTheSource->end() )
				break;
			else
				SourceFunctionAddress=SourceFunctionMembersIter->first;
		}
		SourceBlockAddresses.push_back( SourceFunctionMembersIter->second );
	}
	
	list <DWORD> block_addresses;
	DWORD source_function_addr=0;
	for( FunctionMembersIter=FunctionMembersMapForTheSource->begin();;FunctionMembersIter++ )
	{
		if( FunctionMembersIter==FunctionMembersMapForTheSource->end() || source_function_addr!=FunctionMembersIter->first )
		{
			//Analyze Function, block_addresses contains all the members
			hash_map <DWORD, DWORD> function_match_count;
			if( source_function_addr!=0 )
			{
				list <DWORD>::iterator block_addr_it;
				for (block_addr_it = block_addresses.begin(); block_addr_it != block_addresses.end(); block_addr_it++)
				{
					DWORD block_address=*block_addr_it;

					if (pDumpAddressChecker && (pDumpAddressChecker->IsDumpPair(block_address, 0) || pDumpAddressChecker->IsDumpPair(source_function_addr, 0)))
						Logger.Log(10, LOG_DIFF_MACHINE, "Function: %X Block: %X\r\n", source_function_addr, block_address);

					for (multimap <DWORD, MatchData>::iterator match_map_it = DiffResults->MatchMap.find(block_address);
						match_map_it != DiffResults->MatchMap.end() && match_map_it->first == block_address;
						match_map_it++)
					{
						DWORD target_addr = match_map_it->second.Addresses[1];
						if (pDumpAddressChecker && (pDumpAddressChecker->IsDumpPair(block_address, target_addr) || pDumpAddressChecker->IsDumpPair(source_function_addr, 0)))
							Logger.Log(10, LOG_DIFF_MACHINE, "Function: %X Block: %X:%X\r\n", source_function_addr, match_map_it->second.Addresses[0], target_addr);

						DWORD target_function_address;
						if (TargetController->GetFunctionAddress(target_addr, target_function_address))
						{
							if (pDumpAddressChecker && (pDumpAddressChecker->IsDumpPair(block_address, target_addr) || pDumpAddressChecker->IsDumpPair(source_function_addr, target_function_address)))
								Logger.Log(10, LOG_DIFF_MACHINE, "Function: %X:%X Block: %X:%X\r\n", source_function_addr, target_function_address, block_address, target_addr);

							hash_map <DWORD, DWORD>::iterator function_match_count_it = function_match_count.find(target_function_address);
							if (function_match_count_it == function_match_count.end())
							{
								function_match_count.insert(pair<DWORD, DWORD>(target_function_address, 1));
							}else
							{
								function_match_count_it->second++;
							}
						}
					}
				}
				//source_function_addr
				//We have function_match_count filled up!
				//Get Maximum value in function_match_count
				DWORD maximum_function_match_count=0;
				DWORD chosen_target_function_addr=0;
				for (hash_map <DWORD, DWORD>::iterator it = function_match_count.begin(); it != function_match_count.end(); it++)
				{
					if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(source_function_addr, it->first))
						Logger.Log(10, LOG_DIFF_MACHINE, "%X:%X( %u )\n", source_function_addr, it->first, it->second);

					if (maximum_function_match_count < it->second)
					{
						Logger.Log(10, LOG_DIFF_MACHINE, " New maximum function match count: %d over %d\n", it->second, maximum_function_match_count);
						chosen_target_function_addr = it->first;
						maximum_function_match_count = it->second;
					}
				}

				if( chosen_target_function_addr )
				{
					//Remove Except chosen_target_function_addr from match_map
					if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(source_function_addr, chosen_target_function_addr))
						Logger.Log( 10, LOG_DIFF_MACHINE,  "Choosing ( %X:%X )\n", source_function_addr, chosen_target_function_addr );

					if (DiffResults->MatchMap.find(source_function_addr) == DiffResults->MatchMap.end())
					{
						MatchData match_data;
						memset( &match_data, 0, sizeof( MatchData ) );
						match_data.Type=FUNCTION_MATCH;
						match_data.Addresses[0] = source_function_addr;
						match_data.Addresses[1]=chosen_target_function_addr;
						match_data.MatchRate=100;

						if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
							Logger.Log(10, LOG_DIFF_MACHINE, "%s adding to temporary map %X-%X: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

						pTargetTemporaryMap->insert( MatchMap_Pair( 
							source_function_addr, 
							match_data
							 ) );
					}

					//Remove match entries for specific target_function
					for (block_addr_it = block_addresses.begin(); block_addr_it != block_addresses.end(); block_addr_it++)
					{
						DWORD source_address=*block_addr_it;
						for (multimap <DWORD, MatchData>::iterator it = DiffResults->MatchMap.find(source_address);
							it != DiffResults->MatchMap.end() && it->first == source_address;
						)
						{
							DWORD source_function_address;
							DWORD target_address = it->second.Addresses[1];
							BOOL function_matched=FALSE;
							if (SourceController->GetFunctionAddress(source_address, source_function_address))
							{
								function_matched = TargetController->FindBlockFunctionMatch(target_address, chosen_target_function_addr);
							}

							if (!function_matched)
							{
								if (pDumpAddressChecker && 
									(
										pDumpAddressChecker->IsDumpPair(source_function_address, target_address) ||
										pDumpAddressChecker->IsDumpPair(source_function_address, chosen_target_function_addr)
									)
								)
								Logger.Log(10, LOG_DIFF_MACHINE, "Removing address %X( %X )-%X( %X )\n", source_address, source_function_address, target_address, chosen_target_function_addr);
								it = DiffResults->Erase(it);

							}else
							{
								//Logger.Log( 10, LOG_DIFF_MACHINE,  "Keeping address %X( %X )-%X( %X )\n", Address, AddressToFunctionMapForTheSourceIter->second, target_address, AddressToFunctionMapForTheTargetIter->second );
								it++;
							}
						}
					}
				}

				block_addresses.clear();
				function_match_count.clear();
				//AddressToFunctionMap.clear();
			}

			if( FunctionMembersIter==FunctionMembersMapForTheSource->end() )
				break;
			else
				source_function_addr=FunctionMembersIter->first;
		}
		if( FunctionMembersIter==FunctionMembersMapForTheSource->end() )
			break;

		//Collect BlockAddresses
		block_addresses.push_back(FunctionMembersIter->second);
	}

	SourceController->ClearBlockToFunction();
	TargetController->ClearBlockToFunction();
}

typedef struct _AddressesInfo_
{
	int Overflowed;
	DWORD TheSourceAddress;
	DWORD TheTargetAddress;
} AddressesInfo;

void DiffMachine::DoFingerPrintMatchInsideFunction(DWORD SourceFunctionAddress, list <DWORD> &SourceBlockAddresses, DWORD TargetFunctionAddress, list <DWORD> &TargetBlockAddresses)
{
	//Fingerprint match on SourceBlockAddresses, TargetBlockAddresse
	/*
	list <DWORD>::iterator SourceBlockAddressIter;
	for( SourceBlockAddressIter=SourceBlockAddresses.begin();SourceBlockAddressIter!=SourceBlockAddresses.end();SourceBlockAddressIter++ )
	{
		DWORD SourceAddress=*SourceBlockAddressIter;
		multimap <DWORD, MatchData>:: MatchDataIterator;
		MatchDataIterator=pTemporaryMap->find( SourceAddress );
		if( MatchDataIterator!=pTemporaryMap->end() )
		{
			DWORD TargetAddress=MatchDataIterator->second.Addresses[1];
			TargetBlockAddresse.erase( TargetAddress );
		}
	}*/
	//Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Entry\n", __FUNCTION__ );
	multimap <DWORD,  unsigned char *>::iterator address_fingerprint_hash_map_Iter;
	hash_map <unsigned char *, AddressesInfo, hash_compare_fingerprint> fingerprint_hash_map;
	hash_map <unsigned char *, AddressesInfo, hash_compare_fingerprint>::iterator fingerprint_hash_map_iter;

	list <DWORD>::iterator SourceBlockAddressIter;
	for( SourceBlockAddressIter=SourceBlockAddresses.begin();SourceBlockAddressIter!=SourceBlockAddresses.end();SourceBlockAddressIter++ )
	{
		DWORD SourceAddress=*SourceBlockAddressIter;
		//Logger.Log( 10, LOG_DIFF_MACHINE,  "\tSource=%X\n", SourceAddress );
		address_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(SourceAddress);
		if( address_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() )
		{
			unsigned char *FingerPrint=address_fingerprint_hash_map_Iter->second;
			fingerprint_hash_map_iter=fingerprint_hash_map.find( FingerPrint );
			if( fingerprint_hash_map_iter!=fingerprint_hash_map.end() )
			{
				fingerprint_hash_map_iter->second.Overflowed=TRUE;
			}else
			{
				AddressesInfo OneAddressesInfo;
				OneAddressesInfo.Overflowed=FALSE;
				OneAddressesInfo.TheSourceAddress=SourceAddress;
				OneAddressesInfo.TheTargetAddress=0L;
				fingerprint_hash_map.insert( pair<unsigned char *, AddressesInfo>( FingerPrint, OneAddressesInfo ) );
			}
		}
	}

	list <DWORD>::iterator TargetBlockAddressIter;
	for( TargetBlockAddressIter=TargetBlockAddresses.begin();TargetBlockAddressIter!=TargetBlockAddresses.end();TargetBlockAddressIter++ )
	{
		DWORD TargetAddress=*TargetBlockAddressIter;
		//Logger.Log( 10, LOG_DIFF_MACHINE,  "\tTarget=%X\n", TargetAddress );
		address_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find( TargetAddress );
		if( address_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() )
		{
			unsigned char *FingerPrint=address_fingerprint_hash_map_Iter->second;
			fingerprint_hash_map_iter=fingerprint_hash_map.find( FingerPrint );
			if( fingerprint_hash_map_iter!=fingerprint_hash_map.end() )
			{
				if( fingerprint_hash_map_iter->second.TheTargetAddress!=0L )
					fingerprint_hash_map_iter->second.Overflowed=TRUE;
				else
					fingerprint_hash_map_iter->second.TheTargetAddress=TargetAddress;
			}else
			{
				AddressesInfo OneAddressesInfo;
				OneAddressesInfo.Overflowed=FALSE;
				OneAddressesInfo.TheSourceAddress=0L;
				OneAddressesInfo.TheTargetAddress=TargetAddress;
				fingerprint_hash_map.insert( pair<unsigned char *, AddressesInfo>( FingerPrint, OneAddressesInfo ) );
			}
		}
	}
	for( fingerprint_hash_map_iter=fingerprint_hash_map.begin();
		fingerprint_hash_map_iter!=fingerprint_hash_map.end();
		fingerprint_hash_map_iter++ )
	{
		if( !fingerprint_hash_map_iter->second.Overflowed &&
			fingerprint_hash_map_iter->second.TheSourceAddress!=0L &&
			fingerprint_hash_map_iter->second.TheTargetAddress!=0L )
		{
			//Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: %X %X\n", __FUNCTION__, fingerprint_hash_map_iter->second.TheSourceAddress, fingerprint_hash_map_iter->second.TheTargetAddress );
			//We found matching blocks
			//fingerprint_hash_map_iter->second.TheSourceAddress, fingerprint_hash_map_iter->second.TheTargetAddress
			MatchData match_data;
			memset( &match_data, 0, sizeof( MatchData ) );
			match_data.Type=FINGERPRINT_INSIDE_FUNCTION_MATCH;
			match_data.Addresses[0]=fingerprint_hash_map_iter->second.TheSourceAddress;
			match_data.Addresses[1]=fingerprint_hash_map_iter->second.TheTargetAddress;

			match_data.UnpatchedParentAddress=SourceFunctionAddress;
			match_data.PatchedParentAddress=TargetFunctionAddress;
			match_data.MatchRate=100;

			if(pDumpAddressChecker)
				pDumpAddressChecker->DumpMatchInfo(match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate, "%s Add fingerprint match:\n", __FUNCTION__);
			DiffResults->AddMatchData(match_data, __FUNCTION__ "_2");
		}
	}
	fingerprint_hash_map.clear();
}

void DiffMachine::PrintMatchMapInfo()
{
	multimap <DWORD,  MatchData>::iterator match_map_iter;
	int unique_match_count=0;
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( DiffResults->MatchMap.count( match_map_iter->first )==1 )
			unique_match_count++;
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: unique_match_count=%u\n", __FUNCTION__, unique_match_count );


	//Print Summary
	//TODO: DiffResults->MatchMap -> save to database...
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: %X-%X ( %s )\n", __FUNCTION__, 
			match_map_iter->first, 
			match_map_iter->second.Addresses[1], 
			MatchDataTypeStr[match_map_iter->second.Type] );
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: ** unidentified( 0 )\n", __FUNCTION__ );

	int unpatched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator source_fingerprint_hash_map_Iter;
	for( source_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		source_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->MatchMap.find( source_fingerprint_hash_map_Iter->first )==DiffResults->MatchMap.end() )
		{
			Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: %X ", __FUNCTION__, source_fingerprint_hash_map_Iter->first );
			if( unpatched_unidentified_number%8==7 )
				Logger.Log( 10, LOG_DIFF_MACHINE,  "\n" );
			unpatched_unidentified_number++;
		}
	}
	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: unpatched_unidentified_number=%u\n", __FUNCTION__, unpatched_unidentified_number );

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: ** unidentified( 1 )\n", __FUNCTION__ );

	int patched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator target_fingerprint_hash_map_Iter;
	for( target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		target_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->ReverseAddressMap.find( target_fingerprint_hash_map_Iter->first )==DiffResults->ReverseAddressMap.end() )
		{
			Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: %X ", __FUNCTION__, target_fingerprint_hash_map_Iter->first );
			if( patched_unidentified_number%8==7 )
				Logger.Log( 10, LOG_DIFF_MACHINE,  "\n" );
			patched_unidentified_number++;
		}
	}
	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: patched_unidentified_number=%u\n", __FUNCTION__, patched_unidentified_number );
}


void DiffMachine::ShowDiffMap( DWORD unpatched_address, DWORD patched_address )
{
	DWORD *p_addresses;

	list <DWORD> address_list;
	list <DWORD>::iterator address_list_iter;
	hash_set <DWORD> checked_addresses;
	address_list.push_back( unpatched_address );
	checked_addresses.insert( unpatched_address );

	for( address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	 )
	{
		int addresses_number;
		Logger.Log( 10, LOG_DIFF_MACHINE,  "%s:  address=%X\n", __FUNCTION__, *address_list_iter );
		p_addresses = SourceController->GetMappedAddresses( *address_list_iter, CREF_FROM, &addresses_number );
		if( p_addresses && addresses_number>0 )
		{
			Logger.Log( 10, LOG_DIFF_MACHINE,  "%s:  p_addresses=%X addresses_number=%u\n", __FUNCTION__, p_addresses, addresses_number );
			for( int i=0;i<addresses_number;i++ )
			{
				if( p_addresses[i] )
				{
					if( checked_addresses.find( p_addresses[i] )==checked_addresses.end() )
					{
						address_list.push_back( p_addresses[i] );
						checked_addresses.insert( p_addresses[i] );
					}
				}
			}
			free( p_addresses );
		}
	}
}

void DiffMachine::GetMatchStatistics( 
	DWORD address, 
	int index, 
	int &found_match_number,
	int &found_match_with_difference_number,
	int &not_found_match_number,
	float &match_rate
)
{
	bool debug = false;
	if (pDumpAddressChecker && 
		(
			(index == 0 && pDumpAddressChecker->IsDumpPair(address,0)) ||
			(index == 1 && pDumpAddressChecker->IsDumpPair(0, address))
		)
	)
		debug = true;

	IDAController *ClientManager = SourceController;

	if (index == 1)
		ClientManager = TargetController;

	list <BLOCK> address_list = ClientManager->GetFunctionMemberBlocks(address);
	list <BLOCK>::iterator address_list_iter;

	found_match_number =0;
	not_found_match_number =0;
	found_match_with_difference_number =0;
	float total_match_rate = 0;
	for( address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	 )
	{
		vector<MatchData *> match_data_list = GetMatchData(index, (*address_list_iter).Start);

		if (match_data_list.size()>0)
		{
			for (vector<MatchData *>::iterator it = match_data_list.begin(); it != match_data_list.end(); it++)
			{
				if ((*it)->MatchRate == 100)
				{
					found_match_number++;
				}
				else
				{
					int source_fingerprint_len = 0;
					int target_fingerprint_len = 0;

					PBasicBlock p_basic_block = SourceController->GetBasicBlock((*it)->Addresses[0]);
					if (p_basic_block)
						source_fingerprint_len = p_basic_block->FingerprintLen;
					
					p_basic_block = TargetController->GetBasicBlock((*it)->Addresses[1]);
					if (p_basic_block)
						target_fingerprint_len = p_basic_block->FingerprintLen;

					if (debug || pDumpAddressChecker->IsDumpPair((*it)->Addresses[0], (*it)->Addresses[1]))
						Logger.Log(10, LOG_DIFF_MACHINE | LOG_MATCH_RATE, "%s: Function: %X Different block(%d): %X-%X (%d%%) Fingerprint Lengths (%d:%d)\n", __FUNCTION__, address, index, (*it)->Addresses[0], (*it)->Addresses[1], (*it)->MatchRate, source_fingerprint_len, target_fingerprint_len);

					if (source_fingerprint_len>0 && target_fingerprint_len>0)
						found_match_with_difference_number++;
				}
				total_match_rate += (*it)->MatchRate;
			}
			CleanUpMatchDataList(match_data_list);
		}else
		{
			PBasicBlock p_basic_block = ClientManager->GetBasicBlock((*address_list_iter).Start);
			if (p_basic_block && p_basic_block->FingerprintLen>0)
			{
				if (debug)
					Logger.Log(10, LOG_DIFF_MACHINE | LOG_MATCH_RATE, "%s: Function: %X Non-matched block(%d): %X (fingerprint length: %d)\n", __FUNCTION__, address, index,  (*address_list_iter).Start, p_basic_block->FingerprintLen);

				not_found_match_number++;
			}
		}
	}

	match_rate = total_match_rate / (found_match_number + found_match_with_difference_number + not_found_match_number);
}

int DiffMachine::GetFunctionMatchInfoCount()
{
	DWORD size_to_return=FunctionMatchList.size();
	
	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: size_to_return=%u\n", __FUNCTION__, size_to_return );
	
	return size_to_return;
}

FunctionMatchInfo DiffMachine::GetFunctionMatchInfo( int i )
{
	return FunctionMatchList.at( i );
}

BOOL DiffMachine::IsInUnidentifiedBlockHash( int index, DWORD address )
{
	if( index==0 )
		return TheSourceUnidentifedBlockHash.find( address ) != TheSourceUnidentifedBlockHash.end();
	else
		return TheTargetUnidentifedBlockHash.find( address ) != TheTargetUnidentifedBlockHash.end();
}

int DiffMachine::GetUnidentifiedBlockCount( int index )
{
	if( index==0 )
		return TheSourceUnidentifedBlockHash.size();
	else
		return TheTargetUnidentifedBlockHash.size();
}

CodeBlock DiffMachine::GetUnidentifiedBlock( int index, int i )
{
	/*
	if( index==0 )
		return TheSourceUnidentifedBlockHash.at( i );
	else
		return TheTargetUnidentifedBlockHash.at( i );
		*/

	CodeBlock x;
	memset( &x, 0, sizeof( x ) );
	return x;
}

void DiffMachine::RevokeTreeMatchMapIterInfo( DWORD address, DWORD match_address )
{
	return;
	multimap <DWORD,  MatchData>::iterator match_map_iter;
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
			continue;
		if( match_map_iter->second.Type==TREE_MATCH )
		{
			if( match_map_iter->second.UnpatchedParentAddress==address && match_map_iter->second.PatchedParentAddress==match_address )
			{
				match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
				RevokeTreeMatchMapIterInfo( match_map_iter->first, match_map_iter->second.Addresses[1] );
			}
		}
	}
}

void DiffMachine::RemoveDuplicates()
{
	multimap <DWORD,  MatchData>::iterator match_map_iter;
	multimap <DWORD,  MatchData>::iterator found_match_map_iter;
	multimap <DWORD,  MatchData>::iterator max_match_map_iter;
	if( !DiffResults ||! SourceController ||!TargetController)
		return;

	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
			continue;
		int found_duplicate=FALSE;
		max_match_map_iter=match_map_iter;
		int maximum_matchrate=match_map_iter->second.MatchRate;
		for( found_match_map_iter=DiffResults->MatchMap.find( match_map_iter->first );
			found_match_map_iter!=DiffResults->MatchMap.end() && match_map_iter->first==found_match_map_iter->first;
			found_match_map_iter++ )
		{
			if( !( found_match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
				&&match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
			{
				//Duplicates found
				if( maximum_matchrate<=found_match_map_iter->second.MatchRate )
				{
					found_duplicate=TRUE;
					max_match_map_iter=found_match_map_iter;
					maximum_matchrate=found_match_map_iter->second.MatchRate;
				}
			}
		}
		/*
		if( found_duplicate )
		{
			if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Choosing %X %X match\n", __FUNCTION__, max_match_map_iter->first, max_match_map_iter->second.Addresses[1] );
			DumpMatchMapIterInfo( __FUNCTION__, max_match_map_iter );
			for( found_match_map_iter=DiffResults->MatchMap.find( match_map_iter->first );
				found_match_map_iter!=DiffResults->MatchMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++ )
			{
				if( max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
				{
					if( DebugLevel&1 ) Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Removing %X %X match\n", __FUNCTION__, found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );
					DumpMatchMapIterInfo( __FUNCTION__, found_match_map_iter );
					found_match_map_iter->second.Status|=STATUS_MAPPING_DISABLED;
					RevokeTreeMatchMapIterInfo( found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );

					hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator=DiffResults->ReverseAddressMap.find( found_match_map_iter->second.Addresses[1] );
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
	hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator;
	for( reverse_match_map_iterator=DiffResults->ReverseAddressMap.begin();
		reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end();
		reverse_match_map_iterator++ )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
			continue;
		int found_duplicate=FALSE;
		max_match_map_iter=match_map_iter;
		int maximum_matchrate=match_map_iter->second.MatchRate;
		hash_map <DWORD, DWORD>::iterator found_reverse_match_map_iterator;
		for( found_match_map_iter=DiffResults->ReverseAddressMap.find( match_map_iter->first );
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
			hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator;
			for( found_match_map_iter=DiffResults->ReverseAddressMap.find( match_map_iter->first );
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
					multimap <DWORD,  MatchData>::iterator iter=DiffResults->MatchMap.find( found_match_map_iter->second.Addresses[1] );
					for( ;iter!=DiffResults->MatchMap.end() && iter->first==found_match_map_iter->second.Addresses[1];iter++ )
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

	DiffResults->CleanUp();
}

void DiffMachine::GenerateFunctionMatchInfo()
{
	multimap <DWORD,  MatchData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	FunctionMatchInfo match_info;

	if( !DiffResults ||! SourceController ||!TargetController)
		return;

	ClearFunctionMatchList();
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
		{
			Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: Skipping %X %X\n", __FUNCTION__, match_map_iter->first, match_map_iter->second.Addresses[1] );
			continue;
		}
#ifdef USE_LEGACY_MAP
		multimap <DWORD,  PBasicBlock>::iterator address_hash_map_pIter;
		address_hash_map_pIter = SourceController->GetClientAnalysisInfo()->address_hash_map.find( match_map_iter->first );
		if( address_hash_map_pIter != SourceController->GetClientAnalysisInfo()->address_hash_map.end() )
		{
			PBasicBlock p_basic_block=address_hash_map_pIter->second;
#else
		PBasicBlock p_basic_block = SourceController->GetBasicBlock( match_map_iter->first );

		if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_map_iter->first, 0))
		{
			Logger.Log(11, LOG_DIFF_MACHINE, "%s: %X Block Type: %d\n", __FUNCTION__,
				match_map_iter->first,
				p_basic_block ? p_basic_block->BlockType : -1);
		}

		if( p_basic_block && p_basic_block->BlockType==FUNCTION_BLOCK )
		{
#endif
			match_info.TheSourceAddress=match_map_iter->first;
			match_info.BlockType=p_basic_block->BlockType;
			match_info.EndAddress=p_basic_block->EndAddress;
			match_info.Type=match_map_iter->second.Type;
			match_info.TheTargetAddress=match_map_iter->second.Addresses[1];
			match_info.MatchRate=99;

			if( last_unpatched_addr!=match_info.TheSourceAddress &&
				last_patched_addr!=match_info.TheTargetAddress
			 )
			{
				match_info.TheSourceFunctionName = SourceController->GetName( match_info.TheSourceAddress );
				match_info.TheTargetFunctionName = TargetController->GetName( match_info.TheTargetAddress );
				
				float source_match_rate = 0.0;
				GetMatchStatistics( 
					match_info.TheSourceAddress, 
					0, 
					match_info.MatchCountForTheSource, 
					match_info.MatchCountWithModificationForTheSource, 
					match_info.NoneMatchCountForTheSource,
					source_match_rate
				 );

				float target_match_rate = 0;
				GetMatchStatistics( 
					match_info.TheTargetAddress, 
					1, 
					match_info.MatchCountForTheTarget, 
					match_info.MatchCountWithModificationForTheTarget, 
					match_info.NoneMatchCountForTheTarget,
					target_match_rate
				 );

				float match_rate = (source_match_rate + target_match_rate) / 2;
				match_info.MatchRate = match_rate;

				if (match_rate != 100 && match_info.MatchRate == 100)
				{
					match_info.MatchRate = 99;
				}
					
				FunctionMatchList.push_back( match_info );
			}
			last_unpatched_addr=match_info.TheSourceAddress;
			last_patched_addr=match_info.TheTargetAddress;
		}

		if( p_basic_block )
		{
#ifndef USE_LEGACY_MAP
			free( p_basic_block );
#endif
		}
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: FunctionMatchList.size()=%u\n", __FUNCTION__, FunctionMatchList.size() );
	//////////// Unidentifed Locations

	multimap <DWORD,  PBasicBlock>::iterator address_hash_map_pIter;
	int unpatched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator source_fingerprint_hash_map_Iter;
	for( source_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		source_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->MatchMap.find( source_fingerprint_hash_map_Iter->first )==DiffResults->MatchMap.end() )
		{
#ifdef USE_LEGACY_MAP
			address_hash_map_pIter = SourceController->GetClientAnalysisInfo()->address_hash_map.find( source_fingerprint_hash_map_Iter->first );
			if( address_hash_map_pIter != SourceController->GetClientAnalysisInfo()->address_hash_map.end() )
			{
				PBasicBlock p_basic_block=( PBasicBlock )p_basic_block;
#else
			PBasicBlock p_basic_block = SourceController->GetBasicBlock( source_fingerprint_hash_map_Iter->first );
			if( p_basic_block )
			{
#endif
				if( p_basic_block->BlockType==FUNCTION_BLOCK )
				{
					match_info.TheSourceAddress=p_basic_block->StartAddress;
					match_info.TheSourceFunctionName = SourceController->GetName( match_info.TheSourceAddress );
					match_info.BlockType=p_basic_block->BlockType;
					match_info.EndAddress=p_basic_block->EndAddress;
					match_info.Type=0;
					match_info.TheTargetAddress=0;
					match_info.TheTargetFunctionName=_strdup("");
					match_info.MatchRate=0;
					match_info.MatchCountForTheSource=0;
					match_info.MatchCountWithModificationForTheSource=0;
					match_info.NoneMatchCountForTheSource=0;

					match_info.MatchCountForTheTarget=0;
					match_info.MatchCountWithModificationForTheTarget=0;
					match_info.NoneMatchCountForTheTarget=0;

					FunctionMatchList.push_back( match_info );
				}
				TheSourceUnidentifedBlockHash.insert( p_basic_block->StartAddress );
#ifndef USE_LEGACY_MAP
				free( p_basic_block );
#endif
			}
			unpatched_unidentified_number++;
		}
	}
	
	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: unpatched_unidentified_number=%u\n", __FUNCTION__, TheSourceUnidentifedBlockHash.size() );

	int patched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator target_fingerprint_hash_map_Iter;
	for( target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		target_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->ReverseAddressMap.find( target_fingerprint_hash_map_Iter->first )==DiffResults->ReverseAddressMap.end() )
		{
			PBasicBlock p_basic_block = TargetController->GetBasicBlock( target_fingerprint_hash_map_Iter->first );
			if( p_basic_block )
			{
				if( p_basic_block->BlockType==FUNCTION_BLOCK )
				{
					match_info.TheSourceAddress=0;
					match_info.TheSourceFunctionName=_strdup( "" );
					match_info.BlockType=p_basic_block->BlockType;
					match_info.EndAddress=0;
					match_info.Type=0;
					match_info.TheTargetAddress=p_basic_block->StartAddress;
					match_info.TheTargetFunctionName = TargetController->GetName( match_info.TheTargetAddress );
					match_info.MatchRate=0;
					match_info.MatchCountForTheSource=0;
					match_info.MatchCountWithModificationForTheSource=0;
					match_info.NoneMatchCountForTheSource=0;

					match_info.MatchCountForTheTarget=0;
					match_info.MatchCountWithModificationForTheTarget=0;
					match_info.NoneMatchCountForTheTarget=0;

					FunctionMatchList.push_back( match_info );
				}

				TheTargetUnidentifedBlockHash.insert( p_basic_block->StartAddress );
				free( p_basic_block );
			}

			patched_unidentified_number++;
		}
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "%s: patched_unidentified_number=%u\n", __FUNCTION__, patched_unidentified_number );
}

DWORD DiffMachine::DumpFunctionMatchInfo( int index, DWORD address )
{
	DWORD block_address=address;

	/*
	if( index==0 )
		block_address = SourceController->GetBlockAddress( address );
	else
		block_address = TargetController->GetBlockAddress( address );
	*/

	multimap <DWORD,  MatchData>::iterator match_map_iter;
	if( index==0 )
	{
		SourceController->DumpBlockInfo( block_address );
		match_map_iter=DiffResults->MatchMap.find( block_address );
		while( match_map_iter!=DiffResults->MatchMap.end() &&
			match_map_iter->first==block_address )
		{
			DumpMatchMapIterInfo( "", match_map_iter );
			TargetController->DumpBlockInfo( match_map_iter->second.Addresses[1] );
			match_map_iter++;
		}
	}
	else
	{
		TargetController->DumpBlockInfo( block_address );
		multimap <DWORD, DWORD>::iterator reverse_match_map_iterator;
		reverse_match_map_iterator=DiffResults->ReverseAddressMap.find( block_address );
		if( reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end() )
		{
			//DumpMatchMapIterInfo( "", match_map_iter );
			//TheSource->DumpBlockInfo( match_map_iter->second.Addresses[1] );
			match_map_iter++;
		}
	}

	return 0L;
}

int ReadOneMatchMapCallback( void *arg, int argc, char **argv, char **names )
{
	vector<MatchData *> *p_match_data_list = (vector<MatchData *> *)arg;
	MatchData *match_data=new MatchData();
	if( match_data )
	{
		match_data->Addresses[0]=strtoul10( argv[0] );
		match_data->Addresses[1]=strtoul10( argv[1] );
		match_data->Type=atoi( argv[3] );
		match_data->SubType=atoi( argv[4] );
		match_data->Status=atoi( argv[5] );
		match_data->MatchRate=atoi( argv[6] );
		match_data->UnpatchedParentAddress=strtoul10( argv[7] );
		match_data->PatchedParentAddress=strtoul10( argv[8] );
		p_match_data_list->push_back(match_data);
	}
	return 0;
}

void DiffMachine::RemoveMatchData(DWORD source_address, DWORD target_address)
{
	 for (multimap <DWORD, MatchData>::iterator it = DiffResults->MatchMap.find(source_address);
		it != DiffResults->MatchMap.end() && it->first == source_address;
		it++
		)
	{
		if (it->second.Addresses[1] != target_address)
			continue;

		it = DiffResults->MatchMap.erase(it);
	}

	for (multimap <DWORD, DWORD>::iterator it = DiffResults->ReverseAddressMap.find(target_address);
		it != DiffResults->ReverseAddressMap.end() && it->first == target_address;
		it++)
	{
		if (it->second != source_address)
			continue;

		it = DiffResults->ReverseAddressMap.erase(it);
	}
}

vector<MatchData *> DiffMachine::GetMatchData(int index, DWORD address, BOOL erase)
{
	vector<MatchData *> match_data_list;

	if( !DiffResults && m_DiffDB )
	{
		MatchData match_data;
		memset( &match_data, 0, sizeof( match_data ) );

		if( erase )
		{
			m_DiffDB->ExecuteStatement(ReadOneMatchMapCallback, &match_data_list, "DELETE FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u", SourceID, TargetID, index == 0 ? "TheSourceAddress" : "TheTargetAddress", address);
		}
		else
		{
			m_DiffDB->ExecuteStatement(ReadOneMatchMapCallback, &match_data_list, "SELECT TheSourceAddress, TheTargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u", SourceID, TargetID, index == 0 ? "TheSourceAddress" : "TheTargetAddress", address);
			if( match_data.Addresses[0]!=0 )
			for (vector<MatchData *>::iterator it = match_data_list.begin(); it!=match_data_list.end(); it++)
			{
				Logger.Log(20, LOG_DIFF_MACHINE, "%s: %u 0x%X returns %X-%X\r\n", __FUNCTION__, 
																					index, 
																					address,																					
																					(*it)->Addresses[0],
																					(*it)->Addresses[1]
																				);
			}
		}
	}else
	{
		multimap<DWORD,DWORD> address_pairs;
		
		if( index==1 )
		{
			for (multimap <DWORD, DWORD>::iterator it = DiffResults->ReverseAddressMap.find(address);
				it != DiffResults->ReverseAddressMap.end() && it->first == address;
				it++)
			{
				address_pairs.insert(pair<DWORD,DWORD>(it->second,address));

				if( erase )
				{
					it=DiffResults->ReverseAddressMap.erase(it);
				}
			}
		}
		else
		{
			address_pairs.insert(pair<DWORD, DWORD>(address, 0));
		}
		
		for (multimap<DWORD, DWORD>::iterator it = address_pairs.begin(); it != address_pairs.end(); it++)
		{
			DWORD source_address = it->first;
			DWORD target_address = it->second;

			multimap <DWORD,  MatchData>::iterator match_map_iter;
			for(match_map_iter = DiffResults->MatchMap.find(source_address);
				match_map_iter != DiffResults->MatchMap.end() && match_map_iter->first==source_address;
				match_map_iter++
			)
			{
				if (target_address!=0 && match_map_iter->second.Addresses[1] != target_address)
					continue;

				Logger.Log(20, LOG_DIFF_MACHINE, "%s: %u 0x%X returns %X-%X\r\n", __FUNCTION__, index, source_address, match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1]);

				if( erase )
				{
					//Erase matching reverse address map entries
					match_map_iter = DiffResults->MatchMap.erase(match_map_iter);

					DWORD match_target_address = match_map_iter->second.Addresses[1];
					DWORD match_source_address = match_map_iter->second.Addresses[0];

					for (multimap <DWORD, DWORD>::iterator reverse_match_map_iter = DiffResults->ReverseAddressMap.find(match_target_address);
						reverse_match_map_iter != DiffResults->ReverseAddressMap.end() && reverse_match_map_iter->first == match_target_address;
						reverse_match_map_iter++
					)
					{
						if (reverse_match_map_iter->second == match_source_address)
							reverse_match_map_iter=DiffResults->ReverseAddressMap.erase(reverse_match_map_iter);
					}
				}
				else
				{
					MatchData *new_match_data = new MatchData();
					memcpy(new_match_data, &match_map_iter->second, sizeof(MatchData));
					match_data_list.push_back(new_match_data);
				}
			}
		}
	}

	Logger.Log(20, LOG_DIFF_MACHINE, "%s: %u 0x%X Returns %d entries\r\n", __FUNCTION__, index, address, match_data_list.size());
	return match_data_list;
}

DWORD DiffMachine::GetMatchAddr( int index, DWORD address )
{
	vector<MatchData *> match_data_list = GetMatchData( index, address );
	for (vector<MatchData *>::iterator it = match_data_list.begin();
		it != match_data_list.end();
		it++
	)
	{
		CleanUpMatchDataList(match_data_list);
		return (*it)->Addresses[index == 0 ? 1 : 0];
	}
	return 0L;
}

BOOL DiffMachine::Save(char *DataFile, BYTE Type, DWORD Offset, DWORD dwMoveMethod, hash_set <DWORD> *pTheSourceSelectedAddresses, hash_set <DWORD> *pTheTargetSelectedAddresses )
{
	return FALSE;
}

BOOL DiffMachine::Save(DisassemblyStoreProcessor& OutputDB, hash_set <DWORD> *pTheSourceSelectedAddresses, hash_set <DWORD> *pTheTargetSelectedAddresses )
{
	if( !SourceController || !TargetController)
		return FALSE;

	DeleteMatchInfo( OutputDB );

	Logger.Log(11, LOG_DIFF_MACHINE | LOG_SQL, "Executing %s\n", CREATE_MATCH_MAP_TABLE_STATEMENT);
	OutputDB.ExecuteStatement( NULL, NULL, CREATE_MATCH_MAP_TABLE_STATEMENT );
	OutputDB.ExecuteStatement(NULL, NULL, CREATE_FILE_LIST_TABLE_STATEMENT);
	OutputDB.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT);
	OutputDB.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT);

	Logger.Log(11, LOG_DIFF_MACHINE | LOG_SQL, "Executing %s\n", CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT);
	OutputDB.ExecuteStatement( NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT );
	OutputDB.ExecuteStatement( NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT );

	OutputDB.BeginTransaction();

	OutputDB.ExecuteStatement(NULL, NULL, INSERT_FILE_LIST_TABLE_STATEMENT, "Source", SourceDBName.c_str(), SourceID, SourceFunctionAddress);
	OutputDB.ExecuteStatement(NULL, NULL, INSERT_FILE_LIST_TABLE_STATEMENT, "Target", TargetDBName.c_str(), TargetID, TargetFunctionAddress);

	multimap <DWORD,  MatchData>::iterator match_map_iter;

	Logger.Log( 10, LOG_DIFF_MACHINE,  "DiffResults->MatchMap.size()=%u\n", DiffResults->MatchMap.size() );
	Logger.Log( 10, LOG_DIFF_MACHINE,  "DiffResults->MatchMap.size()=%u\n", DiffResults->MatchMap.size() );

	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( 
			pTheSourceSelectedAddresses &&
			pTheSourceSelectedAddresses->find( match_map_iter->first )==
			pTheSourceSelectedAddresses->end()
		 )
		{
			continue;
		}

		Logger.Log(20, LOG_DIFF_MACHINE, "%s %X-%X: %d%%\n", __FUNCTION__, 
			match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1], match_map_iter->second.MatchRate);

		OutputDB.ExecuteStatement( NULL, NULL, INSERT_MATCH_MAP_TABLE_STATEMENT, 
			SourceController->GetFileID(), 
			TargetController->GetFileID(), 
			match_map_iter->first, 
			match_map_iter->second.Addresses[1], 
			TYPE_MATCH, 
			match_map_iter->second.Type, 
			match_map_iter->second.SubType, 
			match_map_iter->second.Status, 
			match_map_iter->second.MatchRate, 
			match_map_iter->second.UnpatchedParentAddress, 
			match_map_iter->second.PatchedParentAddress );
	}

	Logger.Log( 10, LOG_DIFF_MACHINE,  "FunctionMatchList.size()=%u\n", FunctionMatchList.size() );

	vector <FunctionMatchInfo>::iterator iter;
	for( iter=FunctionMatchList.begin();iter!=FunctionMatchList.end();iter++ )
	{
		Logger.Log(10, LOG_DIFF_MACHINE|LOG_SQL, INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT"\r\n",
			SourceController->GetFileID(),
			TargetController->GetFileID(),
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

		OutputDB.ExecuteStatement(NULL, NULL, INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT,
				SourceController->GetFileID(),
				TargetController->GetFileID(),
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

	OutputDB.EndTransaction();
	return TRUE;
}

int ReadMatchMapCallback( void *arg, int argc, char **argv, char **names )
{
	AnalysisResult *DiffResults=( AnalysisResult * )arg;

	MatchData match_data;
	DWORD SourceAddress=strtoul10( argv[0] );
	DWORD TargetAddress=strtoul10( argv[1] );
	match_data.Type=atoi( argv[3] );
	match_data.SubType=atoi( argv[4] );
	match_data.Status=atoi( argv[5] );
	match_data.MatchRate=atoi( argv[6] );
	match_data.UnpatchedParentAddress=strtoul10( argv[7] );
	match_data.PatchedParentAddress=strtoul10( argv[8] );
	match_data.Addresses[0]=SourceAddress;
	match_data.Addresses[1]=TargetAddress;
	DiffResults->AddMatchData(match_data, __FUNCTION__);
	return 0;
}

int ReadFunctionMatchListCallback( void *arg, int argc, char **argv, char **names )
{
	vector <FunctionMatchInfo> *pFunctionMatchList=( vector <FunctionMatchInfo> * )arg;
	FunctionMatchInfo function_match_info;
	function_match_info.TheSourceAddress=strtoul10( argv[0] );
	function_match_info.EndAddress=strtoul10( argv[1] );
	function_match_info.TheTargetAddress=strtoul10( argv[2] );
	function_match_info.BlockType=atoi( argv[3] );
	function_match_info.MatchRate=atoi( argv[4] );
	function_match_info.TheSourceFunctionName=_strdup( argv[5] );
	function_match_info.Type=atoi( argv[6] );
	function_match_info.TheTargetFunctionName=_strdup( argv[7] );
	function_match_info.MatchCountForTheSource=atoi( argv[8] );
	function_match_info.NoneMatchCountForTheSource=atoi( argv[9] );
	function_match_info.MatchCountWithModificationForTheSource=atoi( argv[10] );
	function_match_info.MatchCountForTheTarget=atoi( argv[11] );
	function_match_info.NoneMatchCountForTheTarget=atoi( argv[12] );
	function_match_info.MatchCountWithModificationForTheTarget=atoi( argv[13] );
	pFunctionMatchList->push_back( function_match_info );
	return 0;
}

struct FileList
{
	string SourceFilename;
	string TargetFilename;
};

char *GetFilename(char *full_pathname)
{
	for (int i = strlen(full_pathname) - 1; i > 0; i--)
	{
		if (full_pathname[i] == '\\')
		{
			return full_pathname + i + 1;
		}
	}

	return full_pathname;
}

int ReadFileListCallback(void *arg, int argc, char **argv, char **names)
{
	FileList *file_list = (FileList *)arg;
	if (file_list)
	{
		if (!stricmp(argv[0], "source"))
		{
			file_list->SourceFilename = GetFilename(argv[1]);
		}
		else if (!stricmp(argv[0], "target"))
		{
			file_list->TargetFilename = GetFilename(argv[1]);
		}
	}
	return 0;
}

// Use your own error codes here
#define SUCCESS                     0L
#define FAILURE_NULL_ARGUMENT       1L
#define FAILURE_API_CALL            2L
#define FAILURE_INSUFFICIENT_BUFFER 3L

DWORD GetBasePathFromPathName(LPCTSTR szPathName,
	LPTSTR  szBasePath,
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
	if ((dwReturnCode = _tcscpy_s(szBasePath, dwBasePathSize, szDrive)) != 0)
	{
		_ftprintf(stderr, TEXT("Error copying string. _tcscpy_s returned %d\n"), dwReturnCode);
		return FAILURE_API_CALL;
	}
	if ((dwReturnCode = _tcscat_s(szBasePath, dwBasePathSize, szDir)) != 0)
	{
		_ftprintf(stderr, TEXT("Error copying string. _tcscat_s returned %d\n"), dwReturnCode);
		return FAILURE_API_CALL;
	}
	return SUCCESS;
}

BOOL DiffMachine::Create(const char *DiffDBFilename)
{
	Logger.Log(10, LOG_DIFF_MACHINE, "%s\n", __FUNCTION__);

	m_DiffDB = new DisassemblyStoreProcessor(DiffDBFilename);
	FileList DiffFileList;
	m_DiffDB->ExecuteStatement(ReadFileListCallback, &DiffFileList, "SELECT Type, Filename FROM " FILE_LIST_TABLE);

	if (DiffFileList.SourceFilename.size() > 0 && DiffFileList.TargetFilename.size() > 0)
	{
		char *DiffDBBasename = (char *)malloc(strlen(DiffDBFilename) + 1);

		if (DiffDBBasename)
		{
			GetBasePathFromPathName(DiffDBFilename, DiffDBBasename, strlen(DiffDBFilename) + 1);
			char *FullSourceDBName = (char *)malloc(strlen(DiffDBBasename) + strlen(DiffFileList.SourceFilename.c_str()) + 1);

			if (FullSourceDBName)
			{
				strcpy(FullSourceDBName, DiffDBBasename);
				strcat(FullSourceDBName, DiffFileList.SourceFilename.c_str());
				SourceDBName = FullSourceDBName;
				free(FullSourceDBName);
			}

			char *FullTargetDBName = (char *)malloc(strlen(DiffDBBasename) + strlen(DiffFileList.TargetFilename.c_str()) + 1);

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

	if (SourceDBName.size()>0 && TargetDBName.size()>0)
	{
		Logger.Log(10, LOG_DIFF_MACHINE, "	Loading %s\n", SourceDBName.c_str());
		m_SourceDB = new DisassemblyStoreProcessor();
		m_SourceDB->CreateDatabase(SourceDBName.c_str());
		SetSource(SourceDBName.c_str(), 1, SourceFunctionAddress);

		Logger.Log(10, LOG_DIFF_MACHINE, "	Loading %s\n", TargetDBName.c_str());
		m_TargetDB = new DisassemblyStoreProcessor();
		m_TargetDB->CreateDatabase(TargetDBName.c_str());
		SetTarget(TargetDBName.c_str(), 1, TargetFunctionAddress);
	}

	return true;
}

BOOL DiffMachine::Load(const char *DiffDBFilename)
{
	Logger.Log(10, LOG_DIFF_MACHINE, "Loading %s\n", DiffDBFilename);
	Create(DiffDBFilename);

	return _Load();
}

BOOL DiffMachine::Load(DisassemblyStoreProcessor* DiffDB)
{
	m_DiffDB = DiffDB;
	m_SourceDB = DiffDB;
	m_TargetDB = DiffDB;

	return _Load();
}

BOOL DiffMachine::_Load()
{
	Logger.Log(10, LOG_DIFF_MACHINE, "%s\n", __FUNCTION__);

	if (SourceController)
	{
		delete SourceController;
		SourceController = NULL;
	}

	SourceController = new IDAController(m_SourceDB);

	Logger.Log(10, LOG_DIFF_MACHINE, "SourceFunctionAddress: %X\n", SourceFunctionAddress);
	SourceController->AddAnalysisTargetFunction(SourceFunctionAddress);
	SourceController->SetFileID(SourceID);

	if (LoadIDAController)
	{
		SourceController->FixFunctionAddresses();
		SourceController->Load();
	}

	if (TargetController)
	{
		delete TargetController;
		TargetController = NULL;
	}

	TargetController = new IDAController(m_TargetDB);
	TargetController->AddAnalysisTargetFunction(TargetFunctionAddress);
	TargetController->SetFileID(TargetID);

	if (LoadIDAController)
	{
		TargetController->FixFunctionAddresses();
		TargetController->Load();
	}

	char *query = "";

	if (ShowFullMatched)
	{
		if (ShowNonMatched)
		{
			query = "SELECT TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget From "
				FUNCTION_MATCH_INFO_TABLE
				" WHERE TheSourceFileID=%u AND TheTargetFileID=%u";
		}
		else
		{
			query = "SELECT TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget From "
				FUNCTION_MATCH_INFO_TABLE
				" WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND MatchRate != 0";
		}
	}
	else
	{
		if (ShowNonMatched)
		{
			query = "SELECT TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget From "
				FUNCTION_MATCH_INFO_TABLE
				" WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND (NoneMatchCountForTheSource != 0 OR NoneMatchCountForTheTarget != 0 OR MatchCountWithModificationForTheSource!=0 OR MatchCountWithModificationForTheTarget !=0 )";
		}
		else
		{
			query = "SELECT TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget From "
				FUNCTION_MATCH_INFO_TABLE
				" WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND (NoneMatchCountForTheSource != 0 OR NoneMatchCountForTheTarget != 0 OR MatchCountWithModificationForTheSource!=0 OR MatchCountWithModificationForTheTarget !=0 ) AND MatchRate != 0";
		}
	}

	m_DiffDB->ExecuteStatement( ReadFunctionMatchListCallback, &FunctionMatchList, query, SourceID, TargetID);

	if (LoadDiffResults)
	{
		DiffResults = new AnalysisResult;

		m_DiffDB->ExecuteStatement(
			ReadMatchMapCallback,
			DiffResults,
			"SELECT TheSourceAddress, TheTargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress From MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u",
			SourceID, TargetID);
	}

	return TRUE;
}

BOOL DiffMachine::DeleteMatchInfo(DisassemblyStoreProcessor& OutputDB )
{
	if( SourceFunctionAddress > 0 && TargetFunctionAddress > 0 )
	{
		SourceController->DeleteMatchInfo( &OutputDB, SourceController->GetFileID(), SourceFunctionAddress );
		TargetController->DeleteMatchInfo( &OutputDB, TargetController->GetFileID(), TargetFunctionAddress );
	}
	else
	{
		OutputDB.ExecuteStatement( NULL, NULL, DELETE_MATCH_MAP_TABLE_STATEMENT, 
			SourceController->GetFileID(), 
			TargetController->GetFileID() );
		
		OutputDB.ExecuteStatement( NULL, NULL, DELETE_FUNCTION_MATCH_INFO_TABLE_STATEMENT, 
			SourceController->GetFileID(), 
			TargetController->GetFileID() );
	}
	return TRUE;
}

char *DiffMachine::GetMatchTypeStr( int Type )
{
	if (Type<sizeof(MatchDataTypeStr) / sizeof(MatchDataTypeStr[0]))
	{
		return MatchDataTypeStr[Type];
	}
	return "Unknown";
}

BREAKPOINTS DiffMachine::ShowUnidentifiedAndModifiedBlocks()
{
	BREAKPOINTS breakpoints;
	vector <FunctionMatchInfo>::iterator iter;

	for (iter = FunctionMatchList.begin(); iter != FunctionMatchList.end(); iter++)
	{
		if (
			(
				(*iter).MatchCountWithModificationForTheSource > 0 ||
				(*iter).MatchCountWithModificationForTheTarget > 0 ||
				(*iter).MatchRate < 100 ||
				(*iter).NoneMatchCountForTheSource > 0 ||
				(*iter).NoneMatchCountForTheTarget > 0
			) &&
			(*iter).MatchRate > 0)
		{

			bool found_source_blocks = false;

			list <BLOCK> source_blocks = SourceController->GetFunctionMemberBlocks((*iter).TheSourceAddress);
			for (list <BLOCK>::iterator source_block = source_blocks.begin(); source_block != source_blocks.end(); source_block++)
			{
				multimap <DWORD, MatchData>::iterator match_map_iter = DiffResults->MatchMap.find((*source_block).Start);

				if (match_map_iter != DiffResults->MatchMap.end())
				{
					Logger.Log(10, LOG_DIFF_MACHINE, "Unmatched: %X", (*source_block).Start);

					if (breakpoints.SourceAddressMap.find((*source_block).Start) == breakpoints.SourceAddressMap.end())
						breakpoints.SourceAddressMap.insert((*source_block).Start);

					found_source_blocks = true;
				}
				else
				{
					while (match_map_iter != DiffResults->MatchMap.end() && (*match_map_iter).first != (*source_block).Start)
					{
						if ((*match_map_iter).second.MatchRate < 100)
						{
							Logger.Log(10, LOG_DIFF_MACHINE, "Modified: %X", (*match_map_iter).first);

							if (breakpoints.SourceAddressMap.find((*source_block).Start) == breakpoints.SourceAddressMap.end())
								breakpoints.SourceAddressMap.insert((*source_block).Start);
							
							found_source_blocks = true;
						}
						match_map_iter++;
					}
				}
			}

			if (found_source_blocks)
			{
				if (breakpoints.SourceFunctionMap.find((*iter).TheTargetAddress) == breakpoints.SourceFunctionMap.end())
					breakpoints.SourceFunctionMap.insert((*iter).TheTargetAddress);
			}

			//Target
			bool found_target_blocks = false;

			list <BLOCK> target_blocks = TargetController->GetFunctionMemberBlocks((*iter).TheTargetAddress);
			for (list <BLOCK>::iterator target_block = target_blocks.begin(); target_block != target_blocks.end(); target_block++)
			{
				multimap <DWORD, DWORD>::iterator reverse_match_map_iter = DiffResults->ReverseAddressMap.find((*target_block).Start);

				if (reverse_match_map_iter == DiffResults->ReverseAddressMap.end())
				{
					Logger.Log(10, LOG_DIFF_MACHINE, "Unmatched: %X", (*target_block).Start);

					if (breakpoints.TargetAddressMap.find((*target_block).Start) == breakpoints.TargetAddressMap.end())
						breakpoints.TargetAddressMap.insert((*target_block).Start);

					found_target_blocks = true;
				}
				else
				{
					for (; reverse_match_map_iter != DiffResults->ReverseAddressMap.end() && reverse_match_map_iter->first == (*target_block).Start; reverse_match_map_iter++)
					{
						multimap <DWORD, MatchData>::iterator match_map_iter = DiffResults->MatchMap.find(reverse_match_map_iter->second);

						while (match_map_iter != DiffResults->MatchMap.end() && (*match_map_iter).first != reverse_match_map_iter->second)
						{
							if ((*match_map_iter).second.MatchRate < 100)
							{
								Logger.Log(10, LOG_DIFF_MACHINE, "Modified: %X", (*match_map_iter).first);

								if (breakpoints.TargetAddressMap.find((*target_block).Start) == breakpoints.TargetAddressMap.end())
									breakpoints.TargetAddressMap.insert((*target_block).Start);
								found_target_blocks = true;
							}
							match_map_iter++;
						}
					}
				}
			}

			if (found_target_blocks)
			{
				if (breakpoints.TargetFunctionMap.find((*iter).TheTargetAddress) == breakpoints.TargetFunctionMap.end())
					breakpoints.TargetFunctionMap.insert((*iter).TheTargetAddress);
			}
		}
	}
	return breakpoints;
}
