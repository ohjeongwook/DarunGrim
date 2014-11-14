#include "DiffMachine.h"
#include <string>
#include <list>
#include <hash_set>
#include <hash_map>
#include <stdlib.h>
#include <tchar.h>

#include "Diff.h"
#include "LogOperation.h"

#define strtoul10( X ) strtoul( X, NULL, 10 )

#define DEBUG_LEVEL 2

using namespace std;
using namespace stdext;
#include "Configuration.h"

char *MatchDataTypeStr[] = { "Name", "Fingerprint", "Two Level Fingerprint", "IsoMorphic Match", "Fingerprint Inside Function", "Function" };

#include "sqlite3.h"

int DebugLevel = 0;

extern LogOperation Logger;

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
	ShowNonMatched(false)
{
	m_DiffDB=NULL;
	DiffResults=NULL;
	SetSource(the_source);
	SetTarget(the_target);
}

void DiffMachine::ClearFunctionMatchInfoList()
{
	vector <FunctionMatchInfo>::iterator iter;
	for( iter=FunctionMatchInfoList.begin();iter!=FunctionMatchInfoList.end();iter++ )
	{
		free( (*iter).TheSourceFunctionName );
		free( (*iter).TheTargetFunctionName );
	}
	FunctionMatchInfoList.clear();
}

DiffMachine::~DiffMachine()
{
	if( DiffResults )
	{
		DiffResults->MatchMap.clear();
		DiffResults->ReverseAddressMap.clear();
	}

	ClearFunctionMatchInfoList();
	
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
			rate=GetStringSimilarity( unpatched_finger_print_str, patched_finger_print_str );
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
	if( DebugLevel>=0 )
		Logger.Log( 10, "%s: match: %x - %x ( %s/%s ) from: %x %x ( Match rate=%u/100 ) Status=%x\n", 
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

	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: DiffResults->MatchMap Size=%u\n", __FUNCTION__, DiffResults->MatchMap.size() );	
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
#ifdef USE_LEGACY_MAP
		multimap <DWORD,  POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter = SourceController->GetClientAnalysisInfo()->address_hash_map.find( match_map_iter->first );
		if( address_hash_map_pIter != SourceController->GetClientAnalysisInfo()->address_hash_map.end() )
		{
			POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
		POneLocationInfo p_one_location_info = SourceController->GetOneLocationInfo(match_map_iter->first);
		if( p_one_location_info )
		{
#endif
			unpatched_addr=match_map_iter->first;
			patched_addr=match_map_iter->second.Addresses[1];
			if( last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr
			 )
			{
				if( p_one_location_info->BlockType==FUNCTION_BLOCK )
				{
				}else
				{
				}
			}
			if( last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			 )
			{
				if( DebugLevel&1 )
					Logger.Log( 10,  "%s: **** Multiple Possibilities\n", __FUNCTION__ );
				DumpMatchMapIterInfo( "", last_match_map_iter );
				DumpMatchMapIterInfo( "", match_map_iter );
			}

			last_match_map_iter=match_map_iter;
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;
#ifndef USE_LEGACY_MAP
			free( p_one_location_info );
#endif
		}
	}

	hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator;
	for( reverse_match_map_iterator=DiffResults->ReverseAddressMap.begin();
		reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end();
		reverse_match_map_iterator++ )
	{
#ifdef USE_LEGACY_MAP
		multimap <DWORD,  POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter = TargetController->GetClientAnalysisInfo()->address_hash_map.find( reverse_match_map_iterator->first );

		if( address_hash_map_pIter != TargetController->GetClientAnalysisInfo()->address_hash_map.end() )
		{
			POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
		POneLocationInfo p_one_location_info=SourceController->GetOneLocationInfo( reverse_match_map_iterator->first );
		if( p_one_location_info )
		{			
#endif
			unpatched_addr=reverse_match_map_iterator->first;
			patched_addr=reverse_match_map_iterator->second;
			
			if( last_unpatched_addr!=unpatched_addr &&
				last_patched_addr!=patched_addr )
			{
				if( p_one_location_info->BlockType==FUNCTION_BLOCK )
				{
				}else
				{
				}
			}
			if( last_unpatched_addr==unpatched_addr &&
				last_patched_addr!=patched_addr
			 )
			{
				if( DebugLevel&1 )
					Logger.Log( 10,  "%s: **** Multiple Possibilities\n", __FUNCTION__ );
				//DumpMatchMapIterInfo( "", match_map_iter );
			}else
			{
			}
			last_unpatched_addr=unpatched_addr;
			last_patched_addr=patched_addr;

			free( p_one_location_info );
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
		MatchData *pMatchData=GetMatchData( index, (*address_list_iter).Start );
		if( pMatchData )
		{
			Logger.Log(10, "Basic Block: %x Match Rate: %d%%\n", (*address_list_iter).Start, pMatchData->MatchRate);
		}
		else
		{
			Logger.Log(10, "Basic Block: %x Has No Match.\n", (*address_list_iter).Start);
		}
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
		MatchData *pMatchData = GetMatchData(index, (*address_list_iter).Start);
		if( pMatchData )
		{
			if( pMatchData->MatchRate < 100 )
			{
				Members.push_back((*address_list_iter).Start);
			}
		}
		else
		{
			Members.push_back((*address_list_iter).Start);
		}
	}
}

bool DiffMachine::TestAnalysis()
{
	return TRUE;
}

bool DiffMachine::DoFunctionLevelMatchOptimizing()
{
	if (DebugFlag  & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING)
		Logger.Log(10, "%s: DoFunctionLevelMatchOptimizing\n", __FUNCTION__);

	vector <FunctionMatchInfo>::iterator iter;
	for( iter=FunctionMatchInfoList.begin();iter!=FunctionMatchInfoList.end();iter++ )
	{
		Logger.Log( 10,  
					"Source FileID: 0x%.8x\n"
					"Target FileID: 0x % .8x\n"
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
			Logger.Log( 10,  "** Unpatched:\n" );
			TestFunctionMatchRate( 0, iter->TheSourceAddress );

			Logger.Log( 10,  "** Patched:\n" );
			TestFunctionMatchRate( 1, iter->TheTargetAddress );
		}

		list <DWORD> SourceMembers;
		RetrieveNonMatchingMembers( 0, iter->TheSourceAddress, SourceMembers );

		list <DWORD> TargetMembers;
		RetrieveNonMatchingMembers( 1, iter->TheTargetAddress, TargetMembers );


		if( DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING )
		{
			Logger.Log( 10,  "Source Members\n" );
			for( list <DWORD>::iterator member_iter = SourceMembers.begin();
				member_iter != SourceMembers.end();
				member_iter++
			 )
			{
				Logger.Log( 10, "0x%x, ", *member_iter );
			}
			Logger.Log( 10,  "\n" );

			Logger.Log( 10,  "Target Members\n" );
			for( list <DWORD>::iterator member_iter = TargetMembers.begin();
				member_iter != TargetMembers.end();
				member_iter++
			 )
			{
				Logger.Log( 10, "0x%x, ", *member_iter );
			}
			Logger.Log( 10,  "\n" );
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
				int MatchRate=GetMatchRate( *source_member_iter, *target_member_iter );

				if( DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING )
					Logger.Log( 10, "%x-%x: %d%%\n", *source_member_iter, *target_member_iter, MatchRate );

				int OrigSourceMatchRate = 0;
				MatchData *pSourceMatchData = GetMatchData( 0, *source_member_iter );
				if( pSourceMatchData )
				{
					OrigSourceMatchRate = pSourceMatchData->MatchRate;
					if( DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING )
						Logger.Log( 10, "\t%x-%x: %d%%\n", *source_member_iter, pSourceMatchData->Addresses[1], pSourceMatchData->MatchRate );
				}

				int OrigTargetMatchRate = 0;
				MatchData *pTargetMatchData = GetMatchData( 1, *target_member_iter );
				if( pTargetMatchData )
				{
					OrigTargetMatchRate = pTargetMatchData->MatchRate;
					if( DebugFlag & DEBUG_FUNCTION_LEVEL_MATCH_OPTIMIZING )
						Logger.Log( 10, "\t%x-%x: %d%%\n", pTargetMatchData->Addresses[0], *target_member_iter, pTargetMatchData->MatchRate );
				}

#define MINMUM_MEANINGFUL_MATCH_RATE 90
				if( MatchRate > MINMUM_MEANINGFUL_MATCH_RATE && MatchRate > OrigSourceMatchRate && MatchRate > OrigTargetMatchRate )
				{
					Logger.Log( 10, "**** Beating Existing Match Rates.\n");
					Logger.Log( 10, "%x-%x: %d%%\n", *source_member_iter, *target_member_iter, MatchRate );
					Logger.Log( 10, "\t%x-%x: %d%%\n", *source_member_iter, pSourceMatchData?pSourceMatchData->Addresses[1]:0, pSourceMatchData?pSourceMatchData->MatchRate:0 );
					Logger.Log( 10, "\t%x-%x: %d%%\n", pTargetMatchData?pTargetMatchData->Addresses[0]:0, *target_member_iter, pTargetMatchData?pTargetMatchData->MatchRate:0 );


					if( pSourceMatchData )
					{
						GetMatchData( 0, *source_member_iter, TRUE );
					}

					if( pTargetMatchData )
					{
						GetMatchData( 1, *target_member_iter, TRUE );
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
						match_data.MatchRate = MatchRate;

						multimap <DWORD, MatchData>::iterator match_map_iter = DiffResults->MatchMap.find(*source_member_iter);
						if ( match_map_iter  != DiffResults->MatchMap.end())
						{
							DiffResults->MatchMap.erase(match_map_iter);
						}

						hash_map <DWORD, DWORD>::iterator reverse_match_map_iter = DiffResults->ReverseAddressMap.find(*source_member_iter);
						if (reverse_match_map_iter != DiffResults->ReverseAddressMap.end())
						{
							DiffResults->ReverseAddressMap.erase(reverse_match_map_iter);
						}

						if (DebugLevel & 1)
							Logger.Log(10, "%s %x-%x: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);
						
						DiffResults->MatchMap.insert( MatchMap_Pair( *source_member_iter, match_data ) );
						DiffResults->ReverseAddressMap.insert( pair<DWORD, DWORD>( *target_member_iter, *source_member_iter ) );
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
							MatchRate,
							0,
							0 );
					}
				}
			}
		}
		Logger.Log( 10,  "\n" );

	}
	return TRUE;
}

bool DiffMachine::Analyze()
{
	multimap <DWORD,  POneLocationInfo>::iterator address_hash_map_pIter;
	multimap <string,  DWORD>::iterator fingerprint_hash_map_pIter;
	multimap <string,  DWORD>::iterator name_hash_map_pIter;
	multimap <DWORD,  PMapInfo>::iterator map_info_hash_map_pIter;
	MATCHMAP TemporaryMatchMap;

	if (!SourceController || !TargetController)
		return FALSE;

	SourceController->LoadOneLocationInfo();
	TargetController->LoadOneLocationInfo();

	DiffResults=new AnalysisResult;

	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: Fingerprint Map Size %u:%u\n", __FUNCTION__, 
			SourceController->GetClientAnalysisInfo()->fingerprint_hash_map.size(), 
			TargetController->GetClientAnalysisInfo()->fingerprint_hash_map.size() );

	// Name Match
	Logger.Log(10, "Name Match\n");

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

					if (DebugLevel & 1)
						Logger.Log(10, "%s %x-%x: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

					TemporaryMatchMap.insert( MatchMap_Pair( 
						name_hash_map_pIter->second, 
						match_data
						 ) );
				}
			}
		}
	}
	Logger.Log(10, "Name Match Ended\n");

	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: Name matched number=%u\n", __FUNCTION__, TemporaryMatchMap.size() );

	int OldMatchMapSize=0;
	while( 1 )
	{
		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: DoFingerPrintMatch\n", __FUNCTION__ );

		DoFingerPrintMatch( &TemporaryMatchMap );
		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: Match Map Size: %u\n", __FUNCTION__, TemporaryMatchMap.size() );

		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: DoIsomorphMatch\n", __FUNCTION__ );

		DoIsomorphMatch( &TemporaryMatchMap );

		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: Match Map Size: %u\n", __FUNCTION__, TemporaryMatchMap.size() );

		if( TemporaryMatchMap.size()>0 )
		{
			AppendToMatchMap( &DiffResults->MatchMap, &TemporaryMatchMap );
		}else
		{
			break;
		}
		PurgeFingerprintHashMap( &TemporaryMatchMap );
		TemporaryMatchMap.clear();

		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: Call DoFunctionMatch\n", __FUNCTION__ );

		DoFunctionMatch( &DiffResults->MatchMap, &TemporaryMatchMap );

		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: One Loop Of Analysis MatchMap size is %u.\n", __FUNCTION__, DiffResults->MatchMap.size() );

		if( OldMatchMapSize==DiffResults->MatchMap.size() )
			break;

		OldMatchMapSize=DiffResults->MatchMap.size();
	}

	//Construct reverse_match_map
	for( multimap <DWORD,  MatchData>::iterator match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		DiffResults->ReverseAddressMap.insert( pair<DWORD, DWORD>( match_map_iter->second.Addresses[1], match_map_iter->first ) );
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
	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: Appending %u Items To MatchMap\n", __FUNCTION__, pTemporaryMap->size() );
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
	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: Delete %u Items from Fingerprint Map( %u-%u )\n", __FUNCTION__, pTemporaryMap->size(), 
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
	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: %u-%u\n", __FUNCTION__, 
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

					if (DebugLevel & 1)
						Logger.Log(10, "%s %x-%x: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

					p_match_map->insert( MatchMap_Pair( 
						fingerprint_hash_map_pIter->second, 
						match_data
						 ) );
				}
			}
		}
	}

	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: Matched pair count=%u\n", __FUNCTION__, p_match_map->size() );
}

MatchRateInfo *DiffMachine::GetMatchRate(DWORD source_address, DWORD target_address, int type, int &MatchRateInfoCount)
{
	int source_addresses_number;
	int target_addresses_number;
	MatchRateInfoCount = 0;

	DWORD *source_addresses = SourceController->GetMappedAddresses(source_address, type, &source_addresses_number);
	DWORD *target_addresses = TargetController->GetMappedAddresses(target_address, type, &target_addresses_number);

	if (source_addresses_number != 0 && target_addresses_number != 0)
	{
		if (DebugLevel & 4)
		{
			Logger.Log(10, "%s: Tree Matching Mapped Address Count: %x( %x ) %x( %x )\n", __FUNCTION__,
				source_addresses_number, source_address,
				target_addresses_number, target_address);

			int i;
			for (i = 0; i < source_addresses_number; i++)
				Logger.Log(10, "%x ", source_addresses[i]);

			Logger.Log(10, "\n\t");

			for (i = 0; i < target_addresses_number; i++)
				Logger.Log(10, "%x ", target_addresses[i]);

			Logger.Log(10, "\n");
		}

		MatchRateInfo *pMatchRateInfoArray = new MatchRateInfo[source_addresses_number*target_addresses_number];

		for (int i = 0; i < source_addresses_number; i++)
		{
			multimap <DWORD, unsigned char *>::iterator source_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(source_addresses[i]);

			for (int j = 0; j < target_addresses_number; j++)
			{
				multimap <DWORD, unsigned char *>::iterator target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.find(target_addresses[j]);

				if (source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
					target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
				{
					pMatchRateInfoArray[MatchRateInfoCount].Source = source_addresses[i];
					pMatchRateInfoArray[MatchRateInfoCount].Target = target_addresses[j];
					pMatchRateInfoArray[MatchRateInfoCount].MatchRate = GetFingerPrintMatchRate(source_fingerprint_hash_map_Iter->second, target_fingerprint_hash_map_Iter->second);
					MatchRateInfoCount++;
				}
				else if (source_fingerprint_hash_map_Iter == SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end() &&
					target_fingerprint_hash_map_Iter == TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end())
				{
					pMatchRateInfoArray[MatchRateInfoCount].Source = source_addresses[i];
					pMatchRateInfoArray[MatchRateInfoCount].Target = target_addresses[j];
					pMatchRateInfoArray[MatchRateInfoCount].MatchRate = 100;
					MatchRateInfoCount++;
				}
			}
		}

		if (source_addresses)
			free(source_addresses);

		if (target_addresses)
			free(target_addresses);

		return pMatchRateInfoArray;
	}
	
	return NULL;
}

void DiffMachine::DoIsomorphMatch(MATCHMAP *pOrigTemporaryMap)
{
	MATCHMAP *pTemporaryMap = pOrigTemporaryMap;
	int types[]={CREF_FROM, CALL, DREF_FROM}; //CREF_TO, DREF_TO

	while( pTemporaryMap->size()>0 )
	{
		int processed_count=0;
		multimap <DWORD,  MatchData>::iterator match_map_iter;
		MATCHMAP *pNewTemporaryMap = new MATCHMAP;

		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: Current match count=%u\n", __FUNCTION__, pTemporaryMap->size() );

		for( match_map_iter=pTemporaryMap->begin(); match_map_iter!=pTemporaryMap->end(); match_map_iter++ )
		{
			for( int type_pos=0; type_pos<sizeof( types )/sizeof( int );type_pos++ )
			{
				int MatchRateInfoCount = 0;
				MatchRateInfo *pMatchRateInfoArray = GetMatchRate(match_map_iter->first, match_map_iter->second.Addresses[1], types[type_pos], MatchRateInfoCount);

				if (pMatchRateInfoArray)
				{
					while (1)
					{
						int MaxMatchRate = 0;
						int max_i = -1;

						for (int i = 0; i < MatchRateInfoCount; i++)
						{
							if (pMatchRateInfoArray[i].MatchRate > MaxMatchRate)
							{
								MaxMatchRate = pMatchRateInfoArray[i].MatchRate;
								max_i = i;
							}
						}

						if (max_i == -1)
							break;

						bool add_match_map = TRUE;
						MATCHMAP *p_compared_match_map[] = {
							&DiffResults->MatchMap,
							pOrigTemporaryMap,
							pNewTemporaryMap,
							pTemporaryMap };

						multimap <DWORD, MatchData>::iterator cur_match_map_iter;
						for (int compare_i = 0; compare_i < sizeof(p_compared_match_map) / sizeof(p_compared_match_map[0]); compare_i++)
						{
							cur_match_map_iter = p_compared_match_map[compare_i]->find(pMatchRateInfoArray[max_i].Source);

							while (cur_match_map_iter != p_compared_match_map[compare_i]->end() &&
								cur_match_map_iter->first == pMatchRateInfoArray[max_i].Source
								)
							{
								if (cur_match_map_iter->second.Addresses[1] == pMatchRateInfoArray[max_i].Target)
								{
									if (DebugLevel & 2)
										Logger.Log(10, "Match is already there %x-%x\n", pMatchRateInfoArray[max_i].Source, pMatchRateInfoArray[max_i].Target);
									add_match_map = FALSE;
									break;
								}
								else if (pMatchRateInfoArray[max_i].MatchRate < cur_match_map_iter->second.MatchRate)
								{
									if (DebugLevel & 2)
										Logger.Log(10, "Another match is already there with higher match rate %x-%x( %u%% )\n",
										pMatchRateInfoArray[max_i].Source,
										cur_match_map_iter->second.Addresses[1]);
									add_match_map = FALSE;
									break;
								}
								cur_match_map_iter++;
							}

							if (!add_match_map)
								break;
						}

						if (add_match_map)
						{
							if (DebugLevel & 2)
								Logger.Log(10, "Adding %x-%x\n", pMatchRateInfoArray[max_i].Source, pMatchRateInfoArray[max_i].Target);

							MatchData match_data;
							memset(&match_data, 0, sizeof(MatchData));
							match_data.Type = TREE_MATCH;
							match_data.SubType = type_pos;
							match_data.Addresses[0] = pMatchRateInfoArray[max_i].Source;
							match_data.Addresses[1] = pMatchRateInfoArray[max_i].Target;
							match_data.MatchRate = pMatchRateInfoArray[max_i].MatchRate;
							match_data.UnpatchedParentAddress = match_map_iter->first;
							match_data.PatchedParentAddress = match_map_iter->second.Addresses[1];

							if (DebugLevel & 1)
								Logger.Log(10, "%s %x-%x: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

							pNewTemporaryMap->insert(MatchMap_Pair(
								pMatchRateInfoArray[max_i].Source,
								match_data
								));

							for (int i = 0; i < MatchRateInfoCount; i++)
							{
								if (pMatchRateInfoArray[i].Source == pMatchRateInfoArray[max_i].Source ||
									pMatchRateInfoArray[i].Target == pMatchRateInfoArray[max_i].Target
									)
								{
									pMatchRateInfoArray[i].MatchRate = 0;
								}
							}
						}
						else
						{
							pMatchRateInfoArray[max_i].MatchRate = 0;
						}
					}

					delete pMatchRateInfoArray;
				}
			}

			processed_count++;

			if( DebugLevel&4 )
			{
				if( processed_count%100==0 || processed_count==pTemporaryMap->size() )
				{
					Logger.Log( 10,  "%s: %u/%u Items processed and produced %u match entries.\n", __FUNCTION__, 
						processed_count, 
						pTemporaryMap->size(), 
						pNewTemporaryMap->size()
					 );
				}
			}
		}

		Logger.Log( 10,  "%s: New Tree Match count=%u\n", __FUNCTION__, pNewTemporaryMap->size() );
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

void DiffMachine::DoFunctionMatch(MATCHMAP *pTemporaryMap, MATCHMAP *pTargetTemporaryMap)
{
	multimap <DWORD, DWORD> *FunctionMembersMapForTheSource;
	multimap <DWORD, DWORD> *FunctionMembersMapForTheTarget;
	multimap <DWORD, DWORD> *AddressToFunctionMapForTheSource;
	multimap <DWORD, DWORD> *AddressToFunctionMapForTheTarget;

	FunctionMembersMapForTheSource = SourceController->LoadFunctionMembersMap();
	FunctionMembersMapForTheTarget = TargetController->LoadFunctionMembersMap();
	AddressToFunctionMapForTheSource = SourceController->LoadAddressToFunctionMap();
	AddressToFunctionMapForTheTarget = TargetController->LoadAddressToFunctionMap();

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
			for( multimap <DWORD,  MatchData>::iterator MatchMapIter=pTemporaryMap->find( SourceFunctionAddress );MatchMapIter!=pTemporaryMap->end();MatchMapIter++ )
			{
				if( MatchMapIter->first!=SourceFunctionAddress )
				{
					break;
				}
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
				DoFingerPrintMatchInsideFunction( pTemporaryMap, SourceFunctionAddress, SourceBlockAddresses, TargetFunctionAddress, TargetBlockAddresses );
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

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	hash_map <DWORD, DWORD> FunctionsMatchCounts;
	list <DWORD> BlockAddresses;
	DWORD TheSourceFunctionAddress=0;
	for( FunctionMembersIter=FunctionMembersMapForTheSource->begin();;FunctionMembersIter++ )
	{
		if( FunctionMembersIter==FunctionMembersMapForTheSource->end() || TheSourceFunctionAddress!=FunctionMembersIter->first )
		{
			//Analyze Function, BlockAddresses contains all the members
			//
			if( TheSourceFunctionAddress!=0 )
			{
				list <DWORD>::iterator BlockAddressesIter;
				for( BlockAddressesIter=BlockAddresses.begin();BlockAddressesIter!=BlockAddresses.end();BlockAddressesIter++ )
				{
					DWORD Address=*BlockAddressesIter;
					if( DebugLevel&2 )
						Logger.Log( 10,  "Function %X-Basic Block %X\r\n", TheSourceFunctionAddress, Address );
					for( multimap <DWORD,  MatchData>::iterator MatchMapIter=pTemporaryMap->find( Address );
						MatchMapIter!=pTemporaryMap->end() && MatchMapIter->first==Address;
						MatchMapIter++ )
					{
						multimap <DWORD, DWORD>::iterator AddressToFunctionMapForTheTargetIter=AddressToFunctionMapForTheTarget->find( MatchMapIter->second.Addresses[1] );
						if( AddressToFunctionMapForTheTargetIter!=AddressToFunctionMapForTheTarget->end() )
						{
							DWORD MatchedFunctionAddress=AddressToFunctionMapForTheTargetIter->second;
							hash_map <DWORD, DWORD>::iterator FunctionsMatchCountsIter;

							//AddressToFunctionMap.insert( pair<DWORD, DWORD>( Address, MatchedFunctionAddress ) );
							FunctionsMatchCountsIter=FunctionsMatchCounts.find( MatchedFunctionAddress );
							if( FunctionsMatchCountsIter==FunctionsMatchCounts.end() )
							{
								FunctionsMatchCounts.insert( pair<DWORD, DWORD>( MatchedFunctionAddress, 1 ) );
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
				hash_map <DWORD, DWORD>::iterator FunctionsMatchCountsIter;
				DWORD MaximumEntries=0;
				DWORD TheChosenTargetFunctionAddress=0;
				for( FunctionsMatchCountsIter=FunctionsMatchCounts.begin();FunctionsMatchCountsIter!=FunctionsMatchCounts.end();FunctionsMatchCountsIter++ )
				{
					if( DebugLevel&2 )
						Logger.Log( 10,  "%x:%x( %u ) ", TheSourceFunctionAddress, FunctionsMatchCountsIter->first, FunctionsMatchCountsIter->second );
					if( MaximumEntries<FunctionsMatchCountsIter->second )
					{
						TheChosenTargetFunctionAddress=FunctionsMatchCountsIter->first;
						MaximumEntries=FunctionsMatchCountsIter->second;
					}
				}
				if( TheChosenTargetFunctionAddress )
				{
					//Remove Except TheChosenTargetFunctionAddress from match_map
					if( DebugLevel&2 )
						Logger.Log( 10,  "=> ( %x:%x )\n", TheSourceFunctionAddress, TheChosenTargetFunctionAddress );
					if( pTemporaryMap->find( TheSourceFunctionAddress )==pTemporaryMap->end() )
					{
						MatchData match_data;
						memset( &match_data, 0, sizeof( MatchData ) );
						match_data.Type=FUNCTION_MATCH;
						match_data.Addresses[0] = TheSourceFunctionAddress;
						match_data.Addresses[1]=TheChosenTargetFunctionAddress;
						match_data.MatchRate=100;

						if (DebugLevel & 1)
							Logger.Log(10, "%s %x-%x: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

						pTargetTemporaryMap->insert( MatchMap_Pair( 
							TheSourceFunctionAddress, 
							match_data
							 ) );
					}
					for( BlockAddressesIter=BlockAddresses.begin();BlockAddressesIter!=BlockAddresses.end();BlockAddressesIter++ )
					{
						DWORD Address=*BlockAddressesIter;
						for( multimap <DWORD,  MatchData>::iterator MatchMapIter=pTemporaryMap->find( Address );MatchMapIter!=pTemporaryMap->end(); )
						{
							if( MatchMapIter->first!=Address )
								break;

							multimap <DWORD, DWORD>::iterator AddressToFunctionMapForTheSourceIter=AddressToFunctionMapForTheSource->find( Address );
							multimap <DWORD, DWORD>::iterator AddressToFunctionMapForTheTargetIter;
							DWORD MatchedAddress=MatchMapIter->second.Addresses[1];
							BOOL Remove=FALSE;
							if( AddressToFunctionMapForTheSourceIter!=AddressToFunctionMapForTheSource->end() )
							{
								for( AddressToFunctionMapForTheTargetIter=AddressToFunctionMapForTheTarget->find( MatchedAddress );
									AddressToFunctionMapForTheTargetIter!=AddressToFunctionMapForTheTarget->end();
									AddressToFunctionMapForTheTargetIter++ )
								{
									if( AddressToFunctionMapForTheTargetIter->first!=MatchedAddress )
										break;
									if( AddressToFunctionMapForTheTargetIter->second==TheChosenTargetFunctionAddress )
									{
										Remove=FALSE;
										break;
									}else
									{
										Remove=TRUE;
									}
								}
							}

							if( Remove )
							{
									//Remove Address from DiffResults->MatchMap
									if( DebugLevel&2 )
										Logger.Log( 10,  "Removing address %x( %x )-%x( %x )\n", Address, AddressToFunctionMapForTheSourceIter->second, MatchedAddress, AddressToFunctionMapForTheTargetIter->second );
									MatchMapIter=pTemporaryMap->erase( MatchMapIter );

							}else
							{
								//Logger.Log( 10,  "Keeping address %x( %x )-%x( %x )\n", Address, AddressToFunctionMapForTheSourceIter->second, MatchedAddress, AddressToFunctionMapForTheTargetIter->second );
								MatchMapIter++;
							}
						}
					}
					if( DebugLevel&2 )
						Logger.Log( 10,  "\n" );
				}

				BlockAddresses.clear();
				FunctionsMatchCounts.clear();
				//AddressToFunctionMap.clear();
			}

			if( FunctionMembersIter==FunctionMembersMapForTheSource->end() )
				break;
			else
				TheSourceFunctionAddress=FunctionMembersIter->first;
		}
		if( FunctionMembersIter==FunctionMembersMapForTheSource->end() )
			break;

		//Collect BlockAddresses
		BlockAddresses.push_back( FunctionMembersIter->second );
	}

	FunctionMembersMapForTheSource->clear();
	delete FunctionMembersMapForTheSource;
	FunctionMembersMapForTheSource = NULL;

	FunctionMembersMapForTheTarget->clear();
	delete FunctionMembersMapForTheTarget;
	FunctionMembersMapForTheTarget = NULL;

	AddressToFunctionMapForTheSource->clear();
	delete AddressToFunctionMapForTheSource;
	AddressToFunctionMapForTheSource = NULL;

	AddressToFunctionMapForTheTarget->clear();
	delete AddressToFunctionMapForTheTarget;
	AddressToFunctionMapForTheTarget = NULL;


}

typedef struct _AddressesInfo_
{
	int Overflowed;
	DWORD TheSourceAddress;
	DWORD TheTargetAddress;
} AddressesInfo;

void DiffMachine::DoFingerPrintMatchInsideFunction(MATCHMAP *pTemporaryMap, DWORD SourceFunctionAddress, list <DWORD> &SourceBlockAddresses, DWORD TargetFunctionAddress, list <DWORD> &TargetBlockAddresses)
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
	//Logger.Log( 10,  "%s: Entry\n", __FUNCTION__ );
	multimap <DWORD,  unsigned char *>::iterator address_fingerprint_hash_map_Iter;
	hash_map <unsigned char *, AddressesInfo, hash_compare_fingerprint> fingerprint_hash_map;
	hash_map <unsigned char *, AddressesInfo, hash_compare_fingerprint>::iterator fingerprint_hash_map_iter;

	list <DWORD>::iterator SourceBlockAddressIter;
	for( SourceBlockAddressIter=SourceBlockAddresses.begin();SourceBlockAddressIter!=SourceBlockAddresses.end();SourceBlockAddressIter++ )
	{
		DWORD SourceAddress=*SourceBlockAddressIter;
		//Logger.Log( 10,  "\tSource=%X\n", SourceAddress );
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
		//Logger.Log( 10,  "\tTarget=%X\n", TargetAddress );
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
			//Logger.Log( 10,  "%s: %x %x\n", __FUNCTION__, fingerprint_hash_map_iter->second.TheSourceAddress, fingerprint_hash_map_iter->second.TheTargetAddress );
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

			if (DebugLevel & 1)
				Logger.Log(10, "%s %x-%x: %d%%\n", __FUNCTION__, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

			pTemporaryMap->insert( MatchMap_Pair( 
				fingerprint_hash_map_iter->second.TheSourceAddress, 
				match_data
				 ) );
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
	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: unique_match_count=%u\n", __FUNCTION__, unique_match_count );


	//Print Summary
	//TODO: DiffResults->MatchMap -> save to database...
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( DebugLevel&1 )
			Logger.Log( 10,  "%s: %x-%x ( %s )\n", __FUNCTION__, 
				match_map_iter->first, 
				match_map_iter->second.Addresses[1], 
				MatchDataTypeStr[match_map_iter->second.Type] );
	}

	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: ** unidentified( 0 )\n", __FUNCTION__ );
	int unpatched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator source_fingerprint_hash_map_Iter;
	for( source_fingerprint_hash_map_Iter = SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		source_fingerprint_hash_map_Iter != SourceController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		source_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->MatchMap.find( source_fingerprint_hash_map_Iter->first )==DiffResults->MatchMap.end() )
		{
			if( DebugLevel&1 )
			{
				Logger.Log( 10,  "%s: %x ", __FUNCTION__, source_fingerprint_hash_map_Iter->first );
				if( unpatched_unidentified_number%8==7 )
					Logger.Log( 10,  "\n" );
			}
			unpatched_unidentified_number++;
		}
	}
	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: unpatched_unidentified_number=%u\n", __FUNCTION__, unpatched_unidentified_number );


	if( DebugLevel&1 )
		Logger.Log( 10,  "%s: ** unidentified( 1 )\n", __FUNCTION__ );
	int patched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator target_fingerprint_hash_map_Iter;
	for( target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		target_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->ReverseAddressMap.find( target_fingerprint_hash_map_Iter->first )==DiffResults->ReverseAddressMap.end() )
		{
			if( DebugLevel&1 ) Logger.Log( 10,  "%s: %x ", __FUNCTION__, target_fingerprint_hash_map_Iter->first );
			if( patched_unidentified_number%8==7 )
				if( DebugLevel&1 ) Logger.Log( 10,  "\n" );
			patched_unidentified_number++;
		}
	}
	if( DebugLevel&1 ) Logger.Log( 10,  "%s: patched_unidentified_number=%u\n", __FUNCTION__, patched_unidentified_number );
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
		if( DebugLevel&1 )
			Logger.Log( 10,  "%s:  address=%x\n", __FUNCTION__, *address_list_iter );
		p_addresses = SourceController->GetMappedAddresses( *address_list_iter, CREF_FROM, &addresses_number );
		if( p_addresses && addresses_number>0 )
		{
			if( DebugLevel&1 )
				Logger.Log( 10,  "%s:  p_addresses=%x addresses_number=%u\n", __FUNCTION__, p_addresses, addresses_number );
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
	IDAController *ClientManager, 
	int index, 
	int *p_found_match_number, 
	int *p_found_match_with_difference_number, 
	int *p_not_found_match_number,
	float &match_rate
)
{
	list <BLOCK> address_list = ClientManager->GetFunctionMemberBlocks(address);
	list <BLOCK>::iterator address_list_iter;

	( *p_found_match_number )=0;
	( *p_not_found_match_number )=0;
	( *p_found_match_with_difference_number )=0;
	float total_match_rate = 0;
	for( address_list_iter=address_list.begin();
		address_list_iter!=address_list.end();
		address_list_iter++
	 )
	{
		MatchData *pMatchData = GetMatchData(index, (*address_list_iter).Start);

		if( pMatchData )
		{
			if( pMatchData->MatchRate==100 )
			{
				( *p_found_match_number )++;
			}else
			{
				( *p_found_match_with_difference_number )++;
			}
			total_match_rate += pMatchData->MatchRate;
		}else
		{
			( *p_not_found_match_number )++;
		}
	}

	match_rate = total_match_rate/address_list.size();
}

int DiffMachine::GetFunctionMatchInfoCount()
{
	DWORD size_to_return=FunctionMatchInfoList.size();
	
	if( DebugLevel&1 ) 
		Logger.Log( 10,  "%s: size_to_return=%u\n", __FUNCTION__, size_to_return );
	
	return size_to_return;
}

FunctionMatchInfo DiffMachine::GetFunctionMatchInfo( int i )
{
	return FunctionMatchInfoList.at( i );
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
	multimap <DWORD,  MatchData>::iterator current_map_iter;
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
			found_match_map_iter!=DiffResults->MatchMap.end() &&
			match_map_iter->first==found_match_map_iter->first;
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
			if( DebugLevel&1 ) Logger.Log( 10,  "%s: Choosing %x %x match\n", __FUNCTION__, max_match_map_iter->first, max_match_map_iter->second.Addresses[1] );
			DumpMatchMapIterInfo( __FUNCTION__, max_match_map_iter );
			for( found_match_map_iter=DiffResults->MatchMap.find( match_map_iter->first );
				found_match_map_iter!=DiffResults->MatchMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++ )
			{
				if( max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
				{
					if( DebugLevel&1 ) Logger.Log( 10,  "%s: Removing %x %x match\n", __FUNCTION__, found_match_map_iter->first, found_match_map_iter->second.Addresses[1] );
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
			if( DebugLevel&1 ) Logger.Log( 10,  "%s: Choosing( reverse ) %x %x match\n", __FUNCTION__, max_match_map_iter->first, max_match_map_iter->second.Addresses[1] );
			DumpMatchMapIterInfo( __FUNCTION__, max_match_map_iter );
			hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator;
			for( found_match_map_iter=DiffResults->ReverseAddressMap.find( match_map_iter->first );
				found_match_map_iter!=DiffResults->ReverseAddressMap.end() &&
				match_map_iter->first==found_match_map_iter->first;
				found_match_map_iter++ )
			{
				if( max_match_map_iter->second.Addresses[1]!=found_match_map_iter->second.Addresses[1] )
				{
					if( DebugLevel&1 ) Logger.Log( 10,  "%s: Removing( reverse ) %x:%x match\n", __FUNCTION__, 
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

	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		 )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
		{
			current_map_iter=match_map_iter;
			match_map_iter++;
			DiffResults->MatchMap.erase( current_map_iter );
			continue;
		}
		match_map_iter++;
	}
	/*
	hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator;
	for( match_map_iter=DiffResults->ReverseAddressMap.begin();
		match_map_iter!=DiffResults->ReverseAddressMap.end();
		 )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
		{
			current_map_iter=match_map_iter;
			match_map_iter++;
			DiffResults->ReverseAddressMap.erase( current_map_iter );
			continue;
		}
		match_map_iter++;
	}*/
}

void DiffMachine::GenerateFunctionMatchInfo()
{
	multimap <DWORD,  MatchData>::iterator match_map_iter;
	DWORD last_unpatched_addr=0;
	DWORD last_patched_addr=0;
	FunctionMatchInfo match_info;

	if( !DiffResults ||! SourceController ||!TargetController)
		return;

	ClearFunctionMatchInfoList();
	for( match_map_iter=DiffResults->MatchMap.begin();
		match_map_iter!=DiffResults->MatchMap.end();
		match_map_iter++ )
	{
		if( match_map_iter->second.Status&STATUS_MAPPING_DISABLED )
		{
			if( DebugLevel&2 )
				Logger.Log( 10,  "%s: Skipping %x %x\n", __FUNCTION__, match_map_iter->first, match_map_iter->second.Addresses[1] );
			continue;
		}
#ifdef USE_LEGACY_MAP
		multimap <DWORD,  POneLocationInfo>::iterator address_hash_map_pIter;
		address_hash_map_pIter = SourceController->GetClientAnalysisInfo()->address_hash_map.find( match_map_iter->first );
		if( address_hash_map_pIter != SourceController->GetClientAnalysisInfo()->address_hash_map.end() )
		{
			POneLocationInfo p_one_location_info=address_hash_map_pIter->second;
#else
		POneLocationInfo p_one_location_info = SourceController->GetOneLocationInfo( match_map_iter->first );

		if( DebugLevel&4 )
			Logger.Log( 10,  "%s: 0x%X Block Type: %d\n", __FUNCTION__, 
				match_map_iter->first, 
				p_one_location_info?p_one_location_info->BlockType:-1 );

		if( p_one_location_info && p_one_location_info->BlockType==FUNCTION_BLOCK )
		{
#endif
			match_info.TheSourceAddress=match_map_iter->first;
			match_info.BlockType=p_one_location_info->BlockType;
			match_info.EndAddress=p_one_location_info->EndAddress;
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
					SourceController, 
					0, 
					&match_info.MatchCountForTheSource, 
					&match_info.MatchCountWithModificationForTheSource, 
					&match_info.NoneMatchCountForTheSource,
					source_match_rate
				 );

				float target_match_rate = 0;
				GetMatchStatistics( 
					match_info.TheTargetAddress, 
					TargetController, 
					1, 
					&match_info.MatchCountForTheTarget, 
					&match_info.MatchCountWithModificationForTheTarget, 
					&match_info.NoneMatchCountForTheTarget,
					target_match_rate
				 );

				float match_rate = (source_match_rate + target_match_rate) / 2;
				match_info.MatchRate = match_rate;

				if (match_rate != 100 && match_info.MatchRate == 100)
				{
					match_info.MatchRate = 99;
				}
					
				FunctionMatchInfoList.push_back( match_info );
			}
			last_unpatched_addr=match_info.TheSourceAddress;
			last_patched_addr=match_info.TheTargetAddress;
		}

		if( p_one_location_info )
		{
#ifndef USE_LEGACY_MAP
			free( p_one_location_info );
#endif
		}
	}
	if( DebugLevel&1 ) Logger.Log( 10,  "%s: FunctionMatchInfoList.size()=%u\n", __FUNCTION__, FunctionMatchInfoList.size() );
	//////////// Unidentifed Locations

	multimap <DWORD,  POneLocationInfo>::iterator address_hash_map_pIter;
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
				POneLocationInfo p_one_location_info=( POneLocationInfo )p_one_location_info;
#else
			POneLocationInfo p_one_location_info = SourceController->GetOneLocationInfo( source_fingerprint_hash_map_Iter->first );
			if( p_one_location_info )
			{
#endif
				if( p_one_location_info->BlockType==FUNCTION_BLOCK )
				{
					match_info.TheSourceAddress=p_one_location_info->StartAddress;
					match_info.TheSourceFunctionName = SourceController->GetName( match_info.TheSourceAddress );
					match_info.BlockType=p_one_location_info->BlockType;
					match_info.EndAddress=p_one_location_info->EndAddress;
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

					FunctionMatchInfoList.push_back( match_info );
				}
				TheSourceUnidentifedBlockHash.insert( p_one_location_info->StartAddress );
#ifndef USE_LEGACY_MAP
				free( p_one_location_info );
#endif
			}
			unpatched_unidentified_number++;
		}
	}
	if( DebugLevel&1 ) Logger.Log( 10,  "%s: unpatched_unidentified_number=%u\n", __FUNCTION__, TheSourceUnidentifedBlockHash.size() );

	int patched_unidentified_number=0;
	multimap <DWORD,  unsigned char *>::iterator target_fingerprint_hash_map_Iter;
	for( target_fingerprint_hash_map_Iter = TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.begin();
		target_fingerprint_hash_map_Iter != TargetController->GetClientAnalysisInfo()->address_fingerprint_hash_map.end();
		target_fingerprint_hash_map_Iter++
	 )
	{
		if( DiffResults->ReverseAddressMap.find( target_fingerprint_hash_map_Iter->first )==DiffResults->ReverseAddressMap.end() )
		{
			//if( DebugLevel&1 ) Logger.Log( 10,  "%s: %x \n", __FUNCTION__, target_fingerprint_hash_map_Iter->first );

			POneLocationInfo p_one_location_info = TargetController->GetOneLocationInfo( target_fingerprint_hash_map_Iter->first );
			if( p_one_location_info )
			{
				if( p_one_location_info->BlockType==FUNCTION_BLOCK )
				{
					match_info.TheSourceAddress=0;
					match_info.TheSourceFunctionName=_strdup( "" );
					match_info.BlockType=p_one_location_info->BlockType;
					match_info.EndAddress=0;
					match_info.Type=0;
					match_info.TheTargetAddress=p_one_location_info->StartAddress;
					match_info.TheTargetFunctionName = TargetController->GetName( match_info.TheTargetAddress );
					match_info.MatchRate=0;
					match_info.MatchCountForTheSource=0;
					match_info.MatchCountWithModificationForTheSource=0;
					match_info.NoneMatchCountForTheSource=0;

					match_info.MatchCountForTheTarget=0;
					match_info.MatchCountWithModificationForTheTarget=0;
					match_info.NoneMatchCountForTheTarget=0;

					FunctionMatchInfoList.push_back( match_info );
				}

				TheTargetUnidentifedBlockHash.insert( p_one_location_info->StartAddress );
				free( p_one_location_info );
			}

			patched_unidentified_number++;
		}
	}
	if( DebugLevel&1 ) Logger.Log( 10,  "%s: patched_unidentified_number=%u\n", __FUNCTION__, patched_unidentified_number );
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
		hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator;
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
	MatchData *match_data=( MatchData * )arg;
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
	}
	return 0;
}

MatchData *DiffMachine::GetMatchData( int index, DWORD address, BOOL erase )
{
	DWORD block_address=address;
	

	if( !DiffResults && m_DiffDB )
	{
		static MatchData match_data;
		memset( &match_data, 0, sizeof( match_data ) );

		if( erase )
		{
			m_DiffDB->ExecuteStatement( ReadOneMatchMapCallback, &match_data, "DELETE FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u", SourceID, TargetID, index==0?"TheSourceAddress":"TheTargetAddress", block_address );
			return NULL;
		}
		else
		{
			m_DiffDB->ExecuteStatement( ReadOneMatchMapCallback, &match_data, "SELECT TheSourceAddress, TheTargetAddress, MatchType, Type, SubType, Status, MatchRate, UnpatchedParentAddress, PatchedParentAddress FROM MatchMap WHERE TheSourceFileID=%u AND TheTargetFileID=%u AND %s=%u", SourceID, TargetID, index==0?"TheSourceAddress":"TheTargetAddress", block_address );
			if( match_data.Addresses[0]!=0 )
			{
				if( DebugLevel&1 ) Logger.Log( 10,  "%s: %u 0x%x Returns %x-%x\r\n", __FUNCTION__, index, block_address, match_data.Addresses[0], match_data.Addresses[1] );
				return &match_data;
			}
		}
	}else
	{
		if( index==1 )
		{
			hash_map <DWORD, DWORD>::iterator reverse_match_map_iterator=DiffResults->ReverseAddressMap.find( block_address );
			if( reverse_match_map_iterator!=DiffResults->ReverseAddressMap.end() )
			{
				block_address=reverse_match_map_iterator->second;

				if( erase )
				{
					DiffResults->ReverseAddressMap.erase( reverse_match_map_iterator );
				}
			}else
			{
				block_address=0;
			}
		}
		
		if( block_address>0 )
		{
			multimap <DWORD,  MatchData>::iterator match_map_iter;
			match_map_iter=DiffResults->MatchMap.find( block_address );
			if( match_map_iter!=DiffResults->MatchMap.end() )
			{
				if( DebugLevel&1 ) Logger.Log( 10,  "%s: %u 0x%x Returns %x-%x\r\n", __FUNCTION__, index, block_address, match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1] );

				if( erase )
				{
					DiffResults->MatchMap.erase( match_map_iter );
					return NULL;
				}

				return &match_map_iter->second;
			}
		}
	}
	if( DebugLevel&1 ) Logger.Log( 10,  "%s: %u 0x%x Returns NULL\r\n", __FUNCTION__, index, block_address );
	return NULL;
}

DWORD DiffMachine::GetMatchAddr( int index, DWORD address )
{
	MatchData *match_data=GetMatchData( index, address );
	if( match_data )
	{
		return match_data->Addresses[index==0?1:0];
	}
	return 0L;
}

BOOL DiffMachine::Save(char *DataFile, BYTE Type, DWORD Offset, DWORD dwMoveMethod, hash_set <DWORD> *pTheSourceSelectedAddresses, hash_set <DWORD> *pTheTargetSelectedAddresses )
{
	return FALSE;
}

BOOL DiffMachine::Save( DBWrapper& OutputDB, hash_set <DWORD> *pTheSourceSelectedAddresses, hash_set <DWORD> *pTheTargetSelectedAddresses )
{
	if( !SourceController || !TargetController)
		return FALSE;

	DeleteMatchInfo( OutputDB );

	Logger.Log( 10, "Executing %s\n", CREATE_MATCH_MAP_TABLE_STATEMENT );
	OutputDB.ExecuteStatement( NULL, NULL, CREATE_MATCH_MAP_TABLE_STATEMENT );
	OutputDB.ExecuteStatement(NULL, NULL, CREATE_FILE_LIST_TABLE_STATEMENT);
	OutputDB.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_SOURCE_ADDRESS_INDEX_STATEMENT);
	OutputDB.ExecuteStatement(NULL, NULL, CREATE_MATCH_MAP_TABLE_TARGET_ADDRESS_INDEX_STATEMENT);

	Logger.Log( 10, "Executing %s\n", CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT );
	OutputDB.ExecuteStatement( NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_STATEMENT );
	OutputDB.ExecuteStatement( NULL, NULL, CREATE_FUNCTION_MATCH_INFO_TABLE_INDEX_STATEMENT );

	OutputDB.BeginTransaction();

	OutputDB.ExecuteStatement(NULL, NULL, INSERT_FILE_LIST_TABLE_STATEMENT, "Source", SourceDBName.c_str(), SourceID, SourceFunctionAddress);
	OutputDB.ExecuteStatement(NULL, NULL, INSERT_FILE_LIST_TABLE_STATEMENT, "Target", TargetDBName.c_str(), TargetID, TargetFunctionAddress);

	multimap <DWORD,  MatchData>::iterator match_map_iter;

	Logger.Log( 10,  "DiffResults->MatchMap.size()=%u\n", DiffResults->MatchMap.size() );
	if( DebugLevel&1 ) 
		Logger.Log( 10,  "DiffResults->MatchMap.size()=%u\n", DiffResults->MatchMap.size() );

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

	if( DebugLevel&1 ) 
		Logger.Log( 10,  "FunctionMatchInfoList.size()=%u\n", FunctionMatchInfoList.size() );

	vector <FunctionMatchInfo>::iterator iter;
	for( iter=FunctionMatchInfoList.begin();iter!=FunctionMatchInfoList.end();iter++ )
	{
		if (DebugLevel & 1) 
			Logger.Log(10, INSERT_FUNCTION_MATCH_INFO_TABLE_STATEMENT"\r\n",
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
	//if( DebugLevel&1 ) Logger.Log( 10,  "%s: %s %s %s %s\n", __FUNCTION__, argv[0], argv[1], argv[2], argv[3] );
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

	DiffResults->MatchMap.insert( MatchMap_Pair( SourceAddress, match_data ) );
	DiffResults->ReverseAddressMap.insert( pair<DWORD, DWORD>( TargetAddress, SourceAddress ) );
	return 0;
}

int ReadFunctionMatchInfoListCallback( void *arg, int argc, char **argv, char **names )
{
	vector <FunctionMatchInfo> *pFunctionMatchInfoList=( vector <FunctionMatchInfo> * )arg;
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
	pFunctionMatchInfoList->push_back( function_match_info );
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
	Logger.Log(10, "%s\n", __FUNCTION__);

	m_DiffDB = new DBWrapper(DiffDBFilename);
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
		Logger.Log(10, "	Loading %s\n", SourceDBName.c_str());
		m_SourceDB = new DBWrapper();
		m_SourceDB->CreateDatabase(SourceDBName.c_str());
		SetSource(SourceDBName.c_str(), 1, SourceFunctionAddress);

		Logger.Log(10, "	Loading %s\n", TargetDBName.c_str());
		m_TargetDB = new DBWrapper();
		m_TargetDB->CreateDatabase(TargetDBName.c_str());
		SetTarget(TargetDBName.c_str(), 1, TargetFunctionAddress);
	}

	return true;
}

BOOL DiffMachine::Load(const char *DiffDBFilename)
{
	Logger.Log(10, "Loading %s\n", DiffDBFilename);
	Create(DiffDBFilename);

	return _Load();
}

BOOL DiffMachine::Load(DBWrapper* DiffDB)
{
	m_DiffDB = DiffDB;
	m_SourceDB = DiffDB;
	m_TargetDB = DiffDB;

	return _Load();
}

BOOL DiffMachine::_Load()
{
	Logger.Log(10, "%s\n", __FUNCTION__);

	if (SourceController)
	{
		delete SourceController;
		SourceController = NULL;
	}

	SourceController = new IDAController(m_SourceDB);

	Logger.Log(10, "SourceFunctionAddress: %x\n", SourceFunctionAddress);
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

	m_DiffDB->ExecuteStatement( ReadFunctionMatchInfoListCallback, &FunctionMatchInfoList, query, SourceID, TargetID);

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

BOOL DiffMachine::DeleteMatchInfo( DBWrapper& OutputDB )
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

	for (iter = FunctionMatchInfoList.begin(); iter != FunctionMatchInfoList.end(); iter++)
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
					Logger.Log(10, "Unmatched: %x", (*source_block).Start);

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
							Logger.Log(10, "Modified: %x", (*match_map_iter).first);

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
				hash_map <DWORD, DWORD>::iterator reverse_match_map_iter = DiffResults->ReverseAddressMap.find((*target_block).Start);

				if (reverse_match_map_iter == DiffResults->ReverseAddressMap.end())
				{
					Logger.Log(10, "Unmatched: %x", (*target_block).Start);

					if (breakpoints.TargetAddressMap.find((*target_block).Start) == breakpoints.TargetAddressMap.end())
						breakpoints.TargetAddressMap.insert((*target_block).Start);

					found_target_blocks = true;
				}
				else
				{
					multimap <DWORD, MatchData>::iterator match_map_iter = DiffResults->MatchMap.find(reverse_match_map_iter->second);

					while (match_map_iter != DiffResults->MatchMap.end() && (*match_map_iter).first != reverse_match_map_iter->second)
					{
						if ((*match_map_iter).second.MatchRate < 100)
						{
							Logger.Log(10, "Modified: %x", (*match_map_iter).first);

							if (breakpoints.TargetAddressMap.find((*target_block).Start) == breakpoints.TargetAddressMap.end())
								breakpoints.TargetAddressMap.insert((*target_block).Start);
							found_target_blocks = true;
						}
						match_map_iter++;
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
