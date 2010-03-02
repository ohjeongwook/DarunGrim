#pragma warning (disable : 4819)

#include <windows.h>
#include "IDATracer.h"
#include "SharedMemory.h"

#undef USE_INTERNAL_DRAWER
#define DEBUG_LEVEL 0

hash_map <mutable_graph_t *,AddressMap *> gMutableGraph2AddressMap;

AddressMap *p_last_address_map=NULL;

AddressMap *GetAddressMap(mutable_graph_t *g)
{
	hash_map <mutable_graph_t *,AddressMap *>::iterator mutable_graph2address_map_iterator=gMutableGraph2AddressMap.find(g);
	if(mutable_graph2address_map_iterator!=gMutableGraph2AddressMap.end())
	{
		return mutable_graph2address_map_iterator->second;
	}
	return NULL;
}

static int idaapi ida_graph_callback(void *param,int code,va_list va)
{
	int result=0;
	static ea_t last_ea=0;
	static bgcolor_t last_color=0x0;

	switch(code)
	{
		case grcode_changed_current:
			// a new graph node became the current node
			// in:	graph_viewer_t *gv
			//			int curnode
			// out: 0-ok,1-forbid to change the current node
			{
				mutable_graph_t *g=get_viewer_graph(va_arg(va,graph_viewer_t *));
				int curnode=va_argi(va,int);
				hash_map <mutable_graph_t *,AddressMap *>::iterator mutable_graph2address_map_iterator=gMutableGraph2AddressMap.find(g);
				if(mutable_graph2address_map_iterator!=gMutableGraph2AddressMap.end())
				{
					AddressMap *p_address_map=mutable_graph2address_map_iterator->second;
					if(
						p_address_map &&
						p_address_map->number2address_map.find(curnode)!=p_address_map->number2address_map.end())
					{
						ea_t ea=p_address_map->number2address_map.find(curnode)->second;
						static const bgcolor_t SELECTION_COLOR = 0x00FF00;
						if(last_ea>0)
							set_item_color(last_ea,last_color);
						last_ea=ea;
						last_color=get_item_color(ea);
						set_item_color(ea,SELECTION_COLOR);
						mark_idaview_for_refresh(ea);
						jumpto(ea,1);
						showAddr(ea);
						refresh_idaview_anyway();
						TForm *tform_ida_view_a=find_tform("IDA View-A");
						if(tform_ida_view_a)
							switchto_tform(tform_ida_view_a,true);
						//set_item_color(ea,last_color);
					}
				}
			}
			break;

		case grcode_user_refresh: 
			// refresh user-defined graph nodes and edges
			// in:	mutable_graph_t *g
			// out: success
			{
				mutable_graph_t *g=va_arg(va,mutable_graph_t *);
				AddressMap *p_address_map=GetAddressMap(g);
				if(!p_address_map)
				{
					p_address_map=p_last_address_map;
					gMutableGraph2AddressMap.insert(pair <mutable_graph_t *,AddressMap *> (g,p_address_map));
				}
				if(p_address_map)
				{
					if(g->empty())
					{
						g->resize(p_address_map->number2address_map.size());
					}
	
					multimap <int,int>::iterator number_map_iter;
					for(
						number_map_iter=p_address_map->number_map.begin();
						number_map_iter!=p_address_map->number_map.end();
						number_map_iter++
					)
					{
						g->add_edge(
							number_map_iter->second,
							number_map_iter->first,
							NULL);
					}
					
					result=true;
				}
			}
			break;

		case grcode_user_text:
			// retrieve text for user-defined graph node
			// in:	mutable_graph_t *g
			//			int node
			//			const char **result
			//			bgcolor_t *bg_color (maybe NULL)
			// out: must return 0,result must be filled
			// NB: do not use anything calling GDI!
			{
				mutable_graph_t *g=va_arg(va,mutable_graph_t *);
				int node=va_arg(va,int);
				const char **text=va_arg(va,const char **);
				bgcolor_t *bgcolor=va_arg(va,bgcolor_t *);

				AddressMap *p_address_map=GetAddressMap(g);
				if(!p_address_map)
				{
					p_address_map=p_last_address_map;
					gMutableGraph2AddressMap.insert(pair <mutable_graph_t *,AddressMap *> (g,p_address_map));
				}
				if(p_address_map)
				{
					#define BUFFER_SIZE 100
					char buffer[BUFFER_SIZE]={0,};
					ea_t address;
	
					address=p_address_map->number2address_map.find(node)->second;
	
					char func_name_buffer[100]={0,};
					get_func_name(address,func_name_buffer,sizeof(func_name_buffer));
					char disasm_buffer[100]={0,};
					generate_disasm_line(
						address,
						disasm_buffer,
						sizeof(disasm_buffer),
						0);
					tag_remove(disasm_buffer,disasm_buffer,sizeof(disasm_buffer));
					qsnprintf(buffer,BUFFER_SIZE,
						"%s!%.8X\n%s",
						func_name_buffer,
						address,
						disasm_buffer);
	
					*text=buffer;	
					if(bgcolor!=NULL)
						*bgcolor=DEFCOLOR;
					result=true;
				}
				qnotused(g);
			}
			break;
	}
	return result;
}

static bool hooked=false;

void DrawTraceResultMap(ea_t current_ea,multimap <ea_t,ea_t> *p_trace_result_map)
{
#ifdef USE_INTERNAL_DRAWER	
	HWND hwnd=NULL;
	char form_name[100];
	qsnprintf(form_name,sizeof(form_name),"Trace Result(%x)",current_ea);

	TForm *form=create_tform(form_name,&hwnd);
	if(hwnd!=NULL)
	{
		if(!hooked)
		{
			hooked=true;
			hook_to_notification_point(HT_GRAPH,ida_graph_callback,NULL);
		}

		AddressMap *p_address_map=new AddressMap;

		int number=0;
		multimap <ea_t,ea_t>::iterator trace_result_map_iter;
		for(
			trace_result_map_iter=p_trace_result_map->begin();
			trace_result_map_iter!=p_trace_result_map->end();
			trace_result_map_iter++
		)
		{
			ea_t addresses[2]={trace_result_map_iter->first,trace_result_map_iter->second};
			for(int i=0;i<2;i++)
			{
				if(p_address_map->address2number_map.find(addresses[i])==p_address_map->address2number_map.end())
				{
					p_address_map->number2address_map.insert(pair <int,ea_t> (number,addresses[i]));
					p_address_map->address2number_map.insert(pair <ea_t,int> (addresses[i],number));
					number++;
				}
			}
			p_address_map->number_map.insert(pair <int,int> (
					p_address_map->address2number_map.find(trace_result_map_iter->first)->second,
					p_address_map->address2number_map.find(trace_result_map_iter->second)->second
				)
			);
		}

		p_last_address_map=p_address_map;
		// get a unique graph id
		netnode id;
		id.create();
		graph_viewer_t *gv=create_graph_viewer(form,id);
		open_tform(form,0); //FORM_TAB|FORM_MDI|FORM_MENU
		if(gv!=NULL)
		{
		}
	}
	else
	{
		close_tform(form,0);
	}
#else

#endif
}

void UhookGraph()
{
	if(hooked)
	{
		unhook_from_notification_point(HT_GRAPH, ida_graph_callback);
	}
}