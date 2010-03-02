#pragma once
#include <gvc.h>
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

class CGraphVizProcessor
{
private:
	Agraph_t *g;
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
	CGraphVizProcessor();
	~CGraphVizProcessor();
	void SetNodeData(DWORD NodeID,LPCSTR NodeName,LPCSTR NodeData,char *FontColor=NULL,char *FillColor=NULL,char *FontSize="18");
	void SetMapData(DWORD src,DWORD dst);
	int RenderToFile(char *format,char *filename);
	list<DrawingInfo *> *GenerateDrawingInfo();
};

