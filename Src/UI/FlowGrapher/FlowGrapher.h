#pragma once
#include <types.h>
#include <graph.h>
#include <windows.h>
#include <stdio.h>

#ifndef dprintf
#include "dprintf.h"
#endif

#include <hash_map>
#include <list>
using namespace std;
using namespace stdext;
#include "DrawingInfo.h"
//#include "MapPipe.h"

class FlowGrapher
{
private:
	Agraph_t *g;
	GVC_t *gvc;

	char *FontColor;
	char *FillColor;
	char *FontSize;

	stdext::hash_map<DWORD,Agnode_t *> AddressToNodeMap;
	stdext::hash_map<Agnode_t *,DWORD> *NodeToUserDataMap;

	list <DrawingInfo *> *ParseXDOTAttributeString(char *buffer);
	void DumpNodeInfo(Agnode_t *n);
	void DumpEdgeInfo(Agedge_t *e);
	char *GetGraphAttribute(Agraph_t *g,char *attr);
	char *GetNodeAttribute(Agnode_t *n, char *attr);
	char *GetEdgeAttribute(Agedge_t *e, char *attr);
	void GetDrawingInfo(DWORD address,list<DrawingInfo *> *p_drawing_info_map,BYTE type,char *str);

public:
	FlowGrapher();
	~FlowGrapher();

	void SetNodeShape(char *fontcolor = NULL, char *fillcolor = NULL, char *fontsize = "18");
	void AddNode(DWORD node_id,LPCSTR node_name,LPCSTR node_data);
	void AddLink(DWORD src, DWORD dst);
	int RenderToFile(char *format,char *filename);
	list<DrawingInfo *> *GetDrawingInfo();
};
