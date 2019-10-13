#pragma warning ( disable: 4819 )
#pragma warning ( disable: 4996 )
#pragma warning ( disable : 4786 )
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include <iostream>
#include <list>

#include <graph.hpp>

#include "IdaIncludes.h"

#include <winsock.h>
#include "SharedSocket.h"
#include "SharedMemory.h"
#include "DataStructure.h"
#include "Configuration.h"

#include "SocketOperation.h"

#define USE_SQLITE_DB

#if defined( USE_SQLITE_DB )
#include "sqlite3.h"
#include "DisassemblyStorage.h"
#include "DataBaseWriter.h"
#endif

using namespace std;

void SaveDGF(bool ask_file_path);

#include "IDAAnalysis.h"
#include "fileinfo.h"

#include "dprintf.h"

ea_t exception_handler_addr=0L;

#define DREF 0
#define CREF 1
#define FUNCTION 2
#define STACK 3
#define NAME 4
#define DISASM_LINE 5
#define DATA_TYPE 6

#include "IDAVerifier.h"

extern HANDLE gLogFile;
static const char SetLogFileVar[]={VT_STR, 0 };
static error_t idaapi SetLogFile( value_t *argv, value_t *res )
{
	if( argv[0].str && argv[0].str[0] )
	{
		gLogFile=OpenLogFile( argv[0].str );
	}
	res->num=1;
	return eOk;
}

char *OutputFilename=NULL;
ea_t StartEA=0;
ea_t EndEA=0;
static const char SaveAnalysisDataArgs[]={VT_STR, VT_LONG, VT_LONG, 0};
static error_t idaapi SaveAnalysisData( value_t *argv, value_t *res )
{
	if( argv[0].str && argv[0].str[0] )
	{
		OutputFilename=strdup( argv[0].str );
	}else
	{
		OutputFilename=NULL;
	}

	StartEA = argv[1].num;
	EndEA = argv[2].num;

	SaveDGF(false);
	res->num=1;
	return eOk;
}

BOOL ConnectToDarunGrim(unsigned short port);
static const char ConnectToDarunGrimArgs[] = { VT_LONG, 0 };
static error_t idaapi ConnectToDarunGrim( value_t *argv, value_t *res )
{
	msg("%s\n", __FUNCTION__);
	OutputFilename=NULL;
	unsigned short port = argv[0].num;

	ConnectToDarunGrim(port);
	res->num=1;
	return eOk;
}

int idaapi init( void )
{
	set_idc_func( "SaveAnalysisData", SaveAnalysisData, SaveAnalysisDataArgs );
	set_idc_func( "ConnectToDarunGrim", ConnectToDarunGrim, ConnectToDarunGrimArgs );
	set_idc_func( "SetLogFile", SetLogFile, SetLogFileVar );
	return PLUGIN_KEEP;
}

void idaapi term( void )
{
	set_idc_func( "SaveAnalysisData", NULL, NULL );
	set_idc_func( "ConnectToDarunGrim", NULL, NULL );
}

bool IsNumber( char *data )
{
	bool is_number=TRUE;
	//hex
	if( strlen( data )>1 && data[strlen( data )-1]=='h' )
	{
		int i=0;
		while( i<strlen( data )-2 )
		{
			if( 
				( '0'<=data[i] && data[i]<='9' ) || 
				( 'a'<=data[i] && data[i]<='f' ) || 
				( 'A'<=data[i] && data[i]<='F' )
			 )
			{
			}else{
				is_number=FALSE;
				break;
			}
			i++;
		}
	}else{
		int i=0;
		while( data[i] )
		{
			if( '0'<=data[i] && data[i]<='9' )
			{
			}else{
				is_number=FALSE;
				break;
			}
			i++;
		}
	}
	return is_number;
}


void MakeCode( ea_t start_addr, ea_t end_addr )
{
	while( 1 ){
		bool converted=TRUE;
		msg( "MakeCode: %X - %X \n", start_addr, end_addr );
		do_unknown_range( start_addr, end_addr-start_addr, false );
		for( ea_t addr=start_addr;addr<=end_addr;addr+=get_item_size( addr ) ) 
		{
			ua_code( addr );
			if( !isCode( getFlags( addr ) ) )
			{
				converted=FALSE;
				break;
			}
		}
		if( converted )
			break;
		end_addr+=get_item_size( end_addr );
	}
}

void FixExceptionHandlers()
{
	char name[1024];

	for( int n=0;n<get_segm_qty();n++ )
	{
		segment_t *seg_p=getnseg( n );
		if( seg_p->type==SEG_XTRN )
		{
			asize_t current_item_size;
			ea_t current_addr;
			for( current_addr=seg_p->startEA;current_addr<seg_p->endEA;current_addr+=current_item_size )
			{
				get_true_name( current_addr, current_addr, name, sizeof( name ) );
				if( !stricmp( name, "_except_handler3" ) || !stricmp( name, "__imp__except_handler3" ) )
				{
					msg( "name=%s\n", name );
					//dref_to
					ea_t sub_exception_handler=get_first_dref_to( current_addr );
					while( sub_exception_handler!=BADADDR )
					{
						exception_handler_addr=sub_exception_handler;
						get_true_name( sub_exception_handler, sub_exception_handler, name, sizeof( name ) );
						msg( "name=%s\n", name );
						ea_t push_exception_handler=get_first_dref_to( sub_exception_handler );
						while( push_exception_handler!=BADADDR )
						{
							msg( "push exception_handler: %X\n", push_exception_handler );
							ea_t push_handlers_structure=get_first_cref_to( push_exception_handler );
							while( push_handlers_structure!=BADADDR )
							{
								msg( "push hanlders structure: %X\n", push_handlers_structure );
								ea_t handlers_structure_start=get_first_dref_from( push_handlers_structure );
								while( handlers_structure_start!=BADADDR )
								{
									char handlers_structure_start_name[100];
									get_true_name( handlers_structure_start, 
										handlers_structure_start, 
										handlers_structure_start_name, 
										sizeof( handlers_structure_start_name ) );
									ea_t handlers_structure=handlers_structure_start;
									while( 1 )
									{
										msg( "handlers_structure: %X\n", handlers_structure );
										char handlers_structure_name[100];
										get_true_name( handlers_structure, 
											handlers_structure, 
											handlers_structure_name, 
											sizeof( handlers_structure_name ) );
										if( ( handlers_structure_name[0]!=NULL && 
											strcmp( handlers_structure_start_name, handlers_structure_name ) ) ||
											isCode( getFlags( handlers_structure ) )
										 )
										{
											msg( "breaking\n" );
											break;
										}
										if( ( handlers_structure-handlers_structure_start )%4==0 )
										{
											int pos=( handlers_structure-handlers_structure_start )/4;
											if( pos%3==1 || pos%3==2 )
											{
												msg( "Checking handlers_structure: %X\n", handlers_structure );

												ea_t exception_handler_routine=get_first_dref_from( handlers_structure );
												while( exception_handler_routine!=BADADDR )
												{
													msg( "Checking exception_handler_routine: %X\n", exception_handler_routine );
													if( !isCode( getFlags( exception_handler_routine ) ) )
													{
														msg( "Reanalyzing exception_handler_routine: %X\n", exception_handler_routine );
														ea_t end_pos=exception_handler_routine;
														while( 1 )
														{
															if( !isCode( getFlags( end_pos ) ) )
																end_pos+=get_item_size( end_pos );
															else
																break;
														}
														if( !isCode( exception_handler_routine ) )
														{
															msg( "routine 01: %X~%X\n", exception_handler_routine, end_pos );
															MakeCode( exception_handler_routine, end_pos );
														}
													}
													exception_handler_routine=get_next_dref_from( handlers_structure, exception_handler_routine );
												}
											}
										}
										msg( "checked handlers_structure: %X\n", handlers_structure );
										handlers_structure+=get_item_size( handlers_structure );
									}
									handlers_structure_start=get_next_dref_from( push_handlers_structure, handlers_structure_start );
								}
								push_handlers_structure=get_next_cref_to( push_exception_handler, push_handlers_structure );
							}
							push_exception_handler=get_next_dref_to( sub_exception_handler, push_exception_handler );
						}

						sub_exception_handler=get_next_dref_to( current_addr, sub_exception_handler );
					}

				}
				current_item_size=get_item_size( current_addr );
			}
		}
	}
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

typedef list<FunctionMatchInfo *> RangeList;
typedef struct _ChooseListObj_ {
	SOCKET socket;
	RangeList range_list;
} ChooseListObj, *PChooseListObj;


const int column_widths[]={16, 32, 5, 5, 16, 32, 5, 5};
const char *column_header[] =
{
	"Address", 
	"Name", 
	"Matched", 
	"Unmatched", 
	"Address", 
	"Name", 
	"Matched", 
	"Unmatched"
};

static ulong idaapi size_callback( void *obj )
{
	RangeList range_list=( ( PChooseListObj )obj )->range_list;
	return range_list.size();
}

static void idaapi line_callback( void *obj, ulong n, char * const *arrptr )
{
	RangeList range_list=( ( PChooseListObj )obj )->range_list;
	RangeList::iterator range_list_itr;
	ulong i;

	qsnprintf( arrptr[0], MAXSTR, "Unknown" );
	qsnprintf( arrptr[1], MAXSTR, "Unknown" );
	qsnprintf( arrptr[2], MAXSTR, "Unknown" );
	qsnprintf( arrptr[3], MAXSTR, "Unknown" );

	if( n==0 )
	{
		for( int i=0;i<qnumber( column_header );i++ )
			qsnprintf( arrptr[i], MAXSTR, column_header[i] );

		return;
	}
	for( range_list_itr=range_list.begin(), i=0;
		range_list_itr!=range_list.end();
		range_list_itr++, i++ )
	{
		if( i==n-1 )
		{
			qsnprintf( arrptr[0], MAXSTR, "%X", ( *range_list_itr )->TheSourceAddress );
			qsnprintf( arrptr[1], MAXSTR, "%s", ( *range_list_itr )->TheSourceFunctionName );

			qsnprintf( arrptr[2], MAXSTR, "%5d", ( *range_list_itr )->MatchCountForTheSource );
			qsnprintf( arrptr[3], MAXSTR, "%5d", ( *range_list_itr )->NoneMatchCountForTheSource );


			qsnprintf( arrptr[4], MAXSTR, "%X", ( *range_list_itr )->TheTargetAddress );
			qsnprintf( arrptr[5], MAXSTR, "%s", ( *range_list_itr )->TheTargetFunctionName );

			qsnprintf( arrptr[6], MAXSTR, "%5d", ( *range_list_itr )->MatchCountForTheTarget );
			qsnprintf( arrptr[7], MAXSTR, "%5d", ( *range_list_itr )->NoneMatchCountForTheTarget );

			break;
		}
	}
}

static void idaapi enter_callback( void *obj, ulong n )
{
	RangeList range_list=( ( PChooseListObj )obj )->range_list;
	RangeList::iterator range_list_itr;
	ulong i;

	for( range_list_itr=range_list.begin(), i=0;
		range_list_itr!=range_list.end();
		range_list_itr++, i++ )
	{
		if( i==n-1 )
		{
			msg( "Jump to %X\n", ( *range_list_itr )->TheSourceAddress );
			jumpto( ( *range_list_itr )->TheSourceAddress );
			SendTLVData( 
				( ( PChooseListObj )obj )->socket, 
				SHOW_MATCH_ADDR, 
				( PBYTE )&( *range_list_itr )->TheSourceAddress, 
				sizeof( DWORD ) );
			break;
		}
	}
}

static int idaapi graph_callback( void *obj, int code, va_list va )
{
	int result=0;
	if( !obj )
		return result;
	switch( code )
	{
		case grcode_dblclicked:	 // a graph node has been double clicked
			// in:	graph_viewer_t *gv
			//			selection_item_t *current_item
			// out: 0-ok, 1-ignore click
		 {
			graph_viewer_t *v	 = va_arg( va, graph_viewer_t * );
			selection_item_t *s = va_arg( va, selection_item_t * );
			//msg( "%X: %sclicked on ", v, code == grcode_clicked ? "" : "dbl" );
			if( s && s->is_node )
			{
				DWORD addr=get_screen_ea();
				//msg( "node %d( %X )\n", s->node, addr );
				msg( "Showing Block %X\n", addr );
				SendTLVData( 
					( ( PChooseListObj )obj )->socket, 
					SHOW_MATCH_ADDR, 
					( PBYTE )&addr, 
					sizeof( DWORD ) );
			}
		 }
		 break;
	}
	return result;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
typedef struct _EARange_ {
	ea_t start;
	ea_t end;
} EARange;

typedef list<EARange> EARangeList;
const int column_widths_for_unidentified_block_choose_list[]={16, 16};
const char *column_header_for_unidentified_block_choose_list[] =
{
	"Start", 
	"End"
};

static ulong idaapi size_callback_for_unidentified_block_choose_list( void *obj )
{
	return ( ( EARangeList * )obj )->size();
}

static void idaapi enter_callback_for_unidentified_block_choose_list( void *obj, ulong n )
{
	EARangeList::iterator range_list_itr;
	ulong i;

	for( range_list_itr=( ( EARangeList * )obj )->begin(), i=0;
		range_list_itr!=( ( EARangeList * )obj )->end();
		range_list_itr++, i++ )
	{
		if( i==n-1 )
		{
			msg( "Jump to %X\n", ( *range_list_itr ).start );
			jumpto( ( *range_list_itr ).start );
			break;
		}
	}	
}

static void idaapi line_callback_for_unidentified_block_choose_list( void *obj, ulong n, char * const *arrptr )
{
	EARangeList::iterator range_list_itr;
	ulong i;

	qsnprintf( arrptr[0], MAXSTR, "Unknown" );
	qsnprintf( arrptr[1], MAXSTR, "Unknown" );


	if( n==0 )
	{
		for( int i=0;i<qnumber( column_header_for_unidentified_block_choose_list );i++ )
			qsnprintf( arrptr[i], MAXSTR, column_header_for_unidentified_block_choose_list[i] );
		return;
	}
	for( range_list_itr=( ( EARangeList * )obj )->begin(), i=0;
		range_list_itr!=( ( EARangeList * )obj )->end();
		range_list_itr++, i++ )
	{
		if( i==n-1 )
		{
			qsnprintf( arrptr[0], MAXSTR, "%X", ( *range_list_itr ).start );
			qsnprintf( arrptr[1], MAXSTR, "%X", ( *range_list_itr ).end );
			break;
		}
	}
}

int idaapi graph_viewer_callback( void *user_data, int notification_code, va_list va )
{
	msg( "graph_viewer_callback called with notification_code=%d\n", notification_code );
	if( notification_code == grcode_dblclicked )
	{
		ea_t addr=get_screen_ea();

		SOCKET socket = (SOCKET) user_data;
		msg( "Showing Block %X(socket=%d)\n", addr, socket );
		SendTLVData( 
			socket,
			SHOW_MATCH_ADDR, 
			( PBYTE )&addr, 
			sizeof( ea_t )
		);
	}
	return 0;
}

ChooseListObj unidentified_block_choose_list_obj;
EARangeList unidentified_block_choose_list;
ChooseListObj matched_block_choose_list_obj;

bool graph_viewer_callback_installed = FALSE;

int ProcessCommandFromDarunGrim( SOCKET data_socket, char type, DWORD length, PBYTE data )
{
	if( type==SEND_ANALYSIS_DATA )
	{
		DataSharer data_sharer;
		DWORD size=0;
		memcpy( &size, data, sizeof( DWORD ) );
		if( !InitDataSharer( &data_sharer, 
			( char * )data+sizeof( DWORD ), 
			size, 
			FALSE ) )
		{
			return 0;
		}
		AnalyzeIDAData( ( bool ( * )( PVOID context, BYTE type, PBYTE data, DWORD length ) )PutData, ( PVOID )&data_sharer, 0, 0 );
	}
	else if (type == UNINDENTIFIED_ADDR || type == MODIFIED_ADDR)
	{
		EARange ea_range;

		int color = 0x000000;
		if (type == UNINDENTIFIED_ADDR)
		{
			color = 0x0000ff;
		}
		else if (type == MODIFIED_ADDR)
		{
			color = 0x00ffff;
		}

		for( DWORD i=0;i<length/( sizeof( DWORD )*2 );i++ )
		{
			ea_range.start = (get_imagebase() & 0xFFFFFFFF00000000) + ((DWORD *)data)[i * 2];
			ea_range.end = (get_imagebase() & 0xFFFFFFFF00000000) + ((DWORD *)data)[i * 2 + 1];
			unidentified_block_choose_list.push_back( ea_range );

			for( 
				ea_t ea=ea_range.start;
				ea < ea_range.end;
				ea=nextthat( ea, ea_range.end, f_isCode, NULL )
			 )
			{
				set_item_color(ea, color);
			}
		}
	}else if( type==MATCHED_ADDR && sizeof( FunctionMatchInfo )<=length )
	{
		FunctionMatchInfo *p_match_info=( FunctionMatchInfo * )data;
		if( p_match_info->BlockType==FUNCTION_BLOCK )
		{
			matched_block_choose_list_obj.range_list.push_back( p_match_info );
		}

		int color = 0x00ff00;
		if (p_match_info->MatchRate != 100)
		{
			color = 0x00ffff;
		}

		for( 
			ea_t ea = (get_imagebase() & 0xFFFFFFFF00000000) + p_match_info->TheSourceAddress;
			ea < (get_imagebase() & 0xFFFFFFFF00000000) + p_match_info->EndAddress;
			ea = nextthat(ea, (get_imagebase() & 0xFFFFFFFF00000000) + p_match_info->EndAddress, f_isCode, NULL)
		 )
		{
			set_item_color(ea, color);
		}
	}
	else if( type==JUMP_TO_ADDR && length>=4 )
	{
		if (sizeof(ea_t)>sizeof(DWORD))
		{
			ea_t orig_addr = (get_imagebase() & 0xFFFFFFFF00000000) + *(DWORD *)data;
			jumpto(orig_addr);
		}
		else
		{
			jumpto(*(DWORD *)data);
		}
	}
	else if( type==COLOR_ADDRESS && length>=sizeof(unsigned long)*3 )
	{
		ea_t start_address = (get_imagebase() & 0xFFFFFFFF00000000) + ((DWORD *)data)[0];
		ea_t end_address = (get_imagebase() & 0xFFFFFFFF00000000) + ((DWORD *)data)[1];
		unsigned long color = (( DWORD * )data)[2];

		for( 
			ea_t ea=start_address;
			ea <= end_address;
			ea=nextthat( ea, end_address, f_isCode, NULL )
		 )
		{
			set_item_color(ea, color);
		}

		if( !graph_viewer_callback_installed )
		{
			TForm *tform = find_tform( "IDA View-A" );
			if( tform )
			{
				graph_viewer_t *graph_viewer = get_graph_viewer( tform );

				if( graph_viewer )
				{
					mutable_graph_t *mutable_graph = get_viewer_graph( graph_viewer );
					if( mutable_graph )
					{
						mutable_graph->set_callback( graph_viewer_callback, ( void * )data_socket );
						graph_viewer_callback_installed = TRUE;
					}
				}
			}
		}
	}
	else if( type==GET_DISASM_LINES && length>=sizeof( CodeBlock ) )
	{
		//dump disasmline
		char *disasm_buffer=NULL;
		CodeBlock *p_code_block=( CodeBlock * )data;
		char op_buffer[100]={0, };
		int current_buffer_offset=0;
		int new_buffer_offset=0;
		for( ea_t current_address=p_code_block->StartAddress;current_address<p_code_block->EndAddress;current_address+=get_item_size( current_address ) )
		{
			generate_disasm_line( current_address, op_buffer, sizeof( op_buffer )-1, 0 );
			tag_remove( op_buffer, op_buffer, sizeof( op_buffer ) );
			strcat_s( op_buffer, "\n" );

			new_buffer_offset=current_buffer_offset+strlen( op_buffer );
			disasm_buffer=( char * )realloc( disasm_buffer, new_buffer_offset+1 );
			memcpy( disasm_buffer+current_buffer_offset, op_buffer, strlen( op_buffer )+1 );
			current_buffer_offset=new_buffer_offset;
		}

		if( disasm_buffer )
		{
			SendTLVData( data_socket, DISASM_LINES, ( PBYTE )disasm_buffer, strlen( disasm_buffer )+1 );
			free( disasm_buffer );
		}else
		{
			SendTLVData( data_socket, DISASM_LINES, ( PBYTE )"", 1 );
		}
	}
	else if( type==SHOW_DATA )
	{
		matched_block_choose_list_obj.socket=data_socket;

		choose2( 
			0, 
			-1, -1, -1, -1, 
			&unidentified_block_choose_list, 
			qnumber( column_header_for_unidentified_block_choose_list ), 
			column_widths_for_unidentified_block_choose_list, 
			size_callback_for_unidentified_block_choose_list, 
			line_callback_for_unidentified_block_choose_list, 
			"Unidentified Blocks", 
			-1, 
			0, 
			NULL, 
			NULL, 
			NULL, 
			NULL, 
			enter_callback_for_unidentified_block_choose_list, 
			NULL, 
			NULL, 
			NULL );
		choose2( 
			0, 
			-1, -1, -1, -1, 
			&matched_block_choose_list_obj, 
			qnumber( column_header ), 
			column_widths, 
			size_callback, 
			line_callback, 
			"Matched Blocks", 
			-1, 
			0, 
			NULL, 
			NULL, 
			NULL, 
			NULL, 
			enter_callback, 
			NULL, 
			NULL, 
			NULL );
#ifdef HT_GRAPH
		hook_to_notification_point( HT_GRAPH, graph_callback, ( void * )&matched_block_choose_list_obj );
#endif
	}
	else if (type == GET_INPUT_NAME)
	{
		char buf[512] = { 0, };
		get_input_file_path(buf, sizeof(buf));
		SendTLVData(data_socket, INPUT_NAME, (PBYTE)buf, strlen(buf) + 1);
	}

	return 0;
}

BOOL ConnectToDarunGrim(unsigned short port)
{
	msg("Connecting to DarunGrim GUI on port %d...\n", port);
	SOCKET data_socket = ConnectToServer("127.0.0.1", port);
	if( data_socket != INVALID_SOCKET )
	{
		msg( "Connected to DarunGrim GUI on port %d\n", port);
		SetSharedSocketDataReceiver( ProcessCommandFromDarunGrim );
		PutSocketToWSAAsyncSelect( data_socket, SharedSocketDataReceiverWndProc, WM_SHARED_SOCKET_EVENT );
		return TRUE;
	}
	else
	{
		msg("Failed to connect to DarunGrim GUI on port %d\n", port);
	}
	return FALSE;
}

bool FileWriterWrapper( PVOID Context, BYTE Type, PBYTE Data, DWORD Length )
{
	BOOL Status=FALSE;
	HANDLE hFile=( HANDLE )Context;
	if( hFile!=INVALID_HANDLE_VALUE )
	{
		DWORD NumberOfBytesWritten;
		Status=WriteFile( 
			hFile, 
			( LPCVOID )&Type, 
			sizeof( Type ), 
			&NumberOfBytesWritten, 
			NULL
		 );
		if( Status && sizeof( Type )==NumberOfBytesWritten )
		{
			Status=WriteFile( 
				hFile, 
				( LPCVOID )&Length, 
				sizeof( Length ), 
				&NumberOfBytesWritten, 
				NULL
			 );
		}else
		{
			Status=FALSE;
		}	
		if( Status && sizeof( Length )==NumberOfBytesWritten )
		{
			Status=WriteFile( 
				hFile, 
				( LPCVOID )Data, 
				Length, 
				&NumberOfBytesWritten, 
				NULL
			 );
		}else
		{
			Status=FALSE;
		}
		if( Status && Length==NumberOfBytesWritten )
		{
		}else
		{
			Status=FALSE;
		}
	}
	return Status;
}

EXTERN_C IMAGE_DOS_HEADER __ImageBase;
void SaveDGF(bool ask_file_path)
{
	long start_tick = GetTickCount();

	FindInvalidFunctionStartAndConnectBrokenFunctionChunk();

	//FixExceptionHandlers();
#ifdef _USE_IDA_SDK_49_OR_UPPER
	char orignal_file_path[1024] = { 0, };
	char root_file_path[1024] = { 0, };
#else
	char *orignal_file_path = strdup(get_input_file_path());
	char *root_file_path = get_root_filename();
#endif
	char *input_file_path = NULL;
#ifdef _USE_IDA_SDK_49_OR_UPPER
	get_input_file_path(orignal_file_path, sizeof(orignal_file_path)-1);
	get_root_filename(root_file_path, sizeof(root_file_path)-1);
#endif
	if (ask_file_path)
	{
		input_file_path = askfile_c(1, "*.dgf", "Select DB File to Output");
		if (!input_file_path)
		{
			return;
		}
	}

	if (input_file_path && strlen(input_file_path)>0)
	{
		int OutputFilename_size = strlen(input_file_path) + 5;
		OutputFilename = (char *)calloc(1, OutputFilename_size);
		if (OutputFilename)
		{
			qstrncpy(OutputFilename, input_file_path, OutputFilename_size);
#define DB_POSTFIX ".dgf"
			if (stricmp(&input_file_path[strlen(input_file_path) - 4], ".dgf"))
			{
#ifdef _USE_IDA_SDK_49_OR_UPPER
				qstrncat(OutputFilename, DB_POSTFIX, OutputFilename_size);
#else
#ifdef _USE_IDA_SDK_47_OR_LOWER
				strncat(OutputFilename, DB_POSTFIX, OutputFilename_size);
#else
				qstrncat(OutputFilename, DB_POSTFIX, OutputFilename_size);
#endif
#endif
			}
			msg("Output file=[%s]\n", OutputFilename);
		}
	}

	if (OutputFilename)
	{
        DisassemblyStorage storage(OutputFilename);
        db.CreateTables();
		db.BeginTransaction();
		AnalyzeIDAData(storage, StartEA, EndEA);
		db.EndTransaction();
		db.CloseDatabase();
	}

	long end_tick = GetTickCount();
	msg("DarunGrim Analysis Finished %.3f sec\n", (float)(end_tick - start_tick) / 1000);
}

void idaapi run( int arg )
{
	msg( "DarunGrim plugin started...\n" );
	if( arg==1 )
	{
		return;
	}

	char dllname[1024];
	GetModuleFileName((HMODULE)&__ImageBase, dllname, sizeof(dllname));
	LoadLibrary(dllname);

	// Display a dialog box
	char *dialog =
		"STARTITEM 0\n"
		"DarunGrim4\n\n"
		"<##Select operation##Save to DGF:r>\n"
		"<Connect to DarunGrim GUI:R>\n"
		"<Find multiple function membership:R>>\n";

	ushort radio = 0;

	if (AskUsingForm_c(dialog, &radio) == 1)
	{
		if (radio == 0)
		{
			SaveDGF(true);
		}
		else if (radio == 1)
		{
			char *dialog =
				"DarunGrim4\n\n"
				"Check Options->Server menu\n"
				"from DarunGrim4 GUI to get the port information\n"
				"<Port:D:10:10::>\n";
			sval_t port = DARUNGRIM_PORT;
			if (AskUsingForm_c(dialog, &port) == 1)
			{
				ConnectToDarunGrim(port);
			}
		}
		else if (radio == 2)
		{
			FindInvalidFunctionStartAndConnectBrokenFunctionChunk();
		}
	}
}

char comment[]="This is a DarunGrim Plugin.";
char help[] =
				"A DarunGrim Plugin module\n"
				"This module let you analyze differences in two binaries.\n"
				"This plugin dumps ida analysis data to DarunGrim Main Program or Database file.\n";

char wanted_name[]="DarunGrim";
char wanted_hotkey[]="Alt-5";

plugin_t PLUGIN=
{
	IDP_INTERFACE_VERSION, 
	0, 									 // plugin flags
	init, 								// initialize
	term, 								// terminate. this pointer may be NULL.
	run, 								 // invoke plugin
	comment, 						 // long comment about the plugin
												// it could appear in the status line
												// or as a hint
	help, 								// multiline help about the plugin
	wanted_name, 				 // the preferred short name of the plugin
	wanted_hotkey				 // the preferred hotkey to run the plugin
};

