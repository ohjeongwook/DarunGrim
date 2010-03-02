#pragma warning(disable:4005)
#pragma warning(disable:4996)
#include <gvc.h>
#include "CGraphVizProcessor.h"
#include "dprintf.h"
#include <string>

using namespace std;

#define MAX_SIZE 1000
int GraphVizInterfaceProcessorDebugLevel=0;

CGraphVizProcessor::CGraphVizProcessor()
{
	aginit();
	/* Create a simple digraph */
	g=agopen("g",AGDIGRAPH);
	NodeToUserDataMap=new stdext::hash_map<Agnode_t *,DWORD>;
}

CGraphVizProcessor::~CGraphVizProcessor()
{
	delete NodeToUserDataMap;
}

char *EscapeString(char *Src)
{
	//<>{}|
	int SrcLen=strlen(Src);
	char *Dst=(char *)malloc(strlen(Src)*2+1);
	int j=0;
	for(int i=0;i<SrcLen+1;i++,j++)
	{
		if(Src[i]=='<' || Src[i]=='>' || Src[i]=='{' || Src[i]=='}' || Src[i]=='|')
		{
			Dst[j]='\\';
			j++;
			Dst[j]=Src[i];
		}else
		{
			Dst[j]=Src[i];
		}
	}
	return Dst;
}

void CGraphVizProcessor::SetNodeData(DWORD NodeID,LPCSTR NodeName,LPCSTR NodeData,char *FontColor,char *FillColor,char *FontSize)
{
	
	Agnode_t *n;
	char name[1024*4];
	//Escape NodeName and NodeData
	char *EscapedNodeName=EscapeString((char *)NodeName);
	char *EscapedNodeData=EscapeString((char *)NodeData);

	_snprintf(name,sizeof(name),
			"{%s|%s}",
			EscapedNodeName,
			EscapedNodeData);
	n=agnode(g,name);
	agsafeset(n,"label",name,"");
	if(NodeData)
		agsafeset(n,"shape","record","");
	else
		agsafeset(n,"shape","rect","");
	agsafeset(n,"fontname","Sans Serif","");
	agsafeset(n,"fontsize",FontSize,"");
	if(FontColor)
	{
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("%s: [fontcolor] set to [%s]\n",__FUNCTION__,FontColor);
		agsafeset(n,"fontcolor",FontColor,"");
	}
	if(FillColor)
	{
		agsafeset(n,"style","filled","");
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("%s: NodeName=%s [fillcolor] set to [%s]\n",__FUNCTION__,NodeName,FillColor);
		agsafeset(n,"fillcolor",FillColor,"");
	}
	AddressToNodeMap.insert(std::pair <DWORD,Agnode_t *>(NodeID,n));
	NodeToUserDataMap->insert(std::pair <Agnode_t *,DWORD>(n,NodeID));
	free(EscapedNodeName);
	free(EscapedNodeData);
}

void CGraphVizProcessor::SetMapData(DWORD src,DWORD dst)
{
	Agedge_t *e;
	stdext::hash_map<DWORD,Agnode_t *>::iterator AddressToNodeMapIterator;
	Agnode_t *src_node=NULL;
	Agnode_t *dst_node=NULL;
	AddressToNodeMapIterator=AddressToNodeMap.find(src);
	if(AddressToNodeMapIterator!=AddressToNodeMap.end())
	{
		src_node=AddressToNodeMapIterator->second;
	}

	AddressToNodeMapIterator=AddressToNodeMap.find(dst);
	if(AddressToNodeMapIterator!=AddressToNodeMap.end())
	{
		dst_node=AddressToNodeMapIterator->second;
	}
	printf("src=%x src_node=%x\n",src,src_node);
	printf("dst=%x dst_node=%x\n",dst,dst_node);
	if(src_node && dst_node)
	{				
		e=agedge(g,src_node,dst_node);
	}

	return;
}

list <DrawingInfo *> *CGraphVizProcessor::ParseXDOTAttributeString(char *buffer)
{
	int pos=0;
	int ch_consumed;
	int n;
	int i;
	list <DrawingInfo *> *p_drawing_infos=new list <DrawingInfo *>;

	if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("%s\n",buffer);
	while(buffer[pos])
	{
		bool is_valid_type=TRUE;
		DrawingInfo *p_drawing_info=(DrawingInfo *)malloc(sizeof(DrawingInfo));	
		memset(p_drawing_info,0,sizeof(DrawingInfo));
		sscanf(buffer+pos,"%c%n",&p_drawing_info->subtype,&ch_consumed);
		pos+=ch_consumed;
		
		printf("Type is [%c]\n",p_drawing_info->subtype);
		switch(p_drawing_info->subtype)
		{
			case 'E':
			{
				//E point_x point_y w h
				//Filled ellipse ((x-point_x)/w)2 + ((y-point_y)/h)2 = 1
				p_drawing_info->count=2;
				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
				sscanf(buffer+pos," %u %u %u %u%n",&p_drawing_info->points[0].x,&p_drawing_info->points[0].y,&p_drawing_info->points[1].x,&p_drawing_info->points[1].y,&ch_consumed);
				pos+=ch_consumed;
				break;
			}
			case 'e':
			{
				//e point_x point_y w h
				//Unfilled ellipse ((x-point_x)/w)2 + ((y-point_y)/h)2 = 1 
				p_drawing_info->count=2;
				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);				
				sscanf(buffer+pos," %u %u %u %u%n",&p_drawing_info->points[0].x,&p_drawing_info->points[0].y,&p_drawing_info->points[1].x,&p_drawing_info->points[1].y,&ch_consumed);
				pos+=ch_consumed;
				break;
			}
			case 'P':
			{
				//P n x1 y1 ... xn yn
				//Filled polygon using the given n points
				sscanf(buffer+pos," %u%n",&p_drawing_info->count,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
					break;
				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
				for(i=0;i<p_drawing_info->count;i++)
				{
					sscanf(buffer+pos," %u %u%n",&p_drawing_info->points[i].x,&p_drawing_info->points[i].y,&ch_consumed);
					pos+=ch_consumed;
				}
				break;
			}
			case 'p':
			{
				//p n x1 y1 ... xn yn
				//Unfilled polygon using the given n points
				sscanf(buffer+pos," %u%n",&p_drawing_info->count,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
					break;				

				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
				for(i=0;i<p_drawing_info->count;i++)
				{
					sscanf(buffer+pos," %u %u%n",&p_drawing_info->points[i].x,&p_drawing_info->points[i].y,&ch_consumed);
					pos+=ch_consumed;
				}
				break;
			}
			case 'L':
			{
				//L n x1 y1 ... xn yn
				//Polyline using the given n points
				sscanf(buffer+pos," %u%n",&p_drawing_info->count,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
					break;				

				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
				for(i=0;i<p_drawing_info->count;i++)
				{
					sscanf(buffer+pos," %u %u%n",&p_drawing_info->points[i].x,&p_drawing_info->points[i].y,&ch_consumed);
					pos+=ch_consumed;
				}
				break;
			}
			case 'B':
			{
				//B n x1 y1 ... xn yn
				//B-spline using the given n control points
				sscanf(buffer+pos," %u%n",&p_drawing_info->count,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
					break;				

				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
				for(i=0;i<p_drawing_info->count;i++)
				{
					sscanf(buffer+pos," %u %u%n",&p_drawing_info->points[i].x,&p_drawing_info->points[i].y,&ch_consumed);
					pos+=ch_consumed;
				}
				break;
			}
			case 'b':
			{
				//b n x1 y1 ... xn yn
				//Filled B-spline using the given n control points (1.1)
				sscanf(buffer+pos," %u%n",&p_drawing_info->count,&ch_consumed);
				pos+=ch_consumed;
				printf("\tp_drawing_info->count=%u\n",p_drawing_info->count);
				if(MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
					break;

				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
				for(i=0;i<p_drawing_info->count;i++)
				{
					sscanf(buffer+pos," %u %u%n",&p_drawing_info->points[i].x,&p_drawing_info->points[i].y,&ch_consumed);
					pos+=ch_consumed;
				}
				break;
			}
			case 'T':
			{
				//T x y j w n -c1c2...cn
				//Text drawn using the baseline point (x,y). The text consists of the n characters following '-'. 
				//The text should be left-aligned (centered, right-aligned) on the point if j is -1 (0, 1), 
				//respectively. The value w gives the width of the text as computed by the library.
				p_drawing_info->count=2;
				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);				
				sscanf(buffer+pos," %u %u %u %u %u%n",
					&p_drawing_info->points[0].x,
					&p_drawing_info->points[0].y,
					&p_drawing_info->points[1].y, //j
					&p_drawing_info->points[1].x, //w
					&n,
					&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<n || n<0)
					break;				

				p_drawing_info->text=(char *)malloc(sizeof(char)*(n+2));
				memset(p_drawing_info->text,0,n+2);
				char format_str[20];
				_snprintf(format_str,sizeof(format_str)," -%%%uc%%n",n);
				sscanf(buffer+pos,format_str,p_drawing_info->text,&ch_consumed);
				pos+=ch_consumed;
				break;
			}
			case 'C':
			{
				//C n -c1c2...cn
				//Set fill color. The color value consists of the n characters following '-'. (1.1)
				sscanf(buffer+pos," %u%n",&n,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<n || n<0)
					break;				

				p_drawing_info->text=(char *)malloc(sizeof(char)*(n+1));
				memset(p_drawing_info->text,0,n+1);
				char format_str[20];
				_snprintf(format_str,sizeof(format_str)," -%%%uc%%n",n);
				printf("\tformat_str=%s\n",format_str);
				sscanf(buffer+pos,format_str,p_drawing_info->text,&ch_consumed);
				printf("\tp_drawing_info->text=%s\n",p_drawing_info->text);
				pos+=ch_consumed;
				break;
			}
			case 'c':
			{
				//c n -c1c2...cn
				//Set pen color. The color value consists of the n characters following '-'. (1.1)
				sscanf(buffer+pos," %u%n",&n,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<n || n<0)
					break;				

				printf("\tn=%u\n",n);
				p_drawing_info->text=(char *)malloc(sizeof(char)*(n+1));
				memset(p_drawing_info->text,0,n+1);

				char format_str[20];
				_snprintf(format_str,sizeof(format_str)," -%%%uc%%n",n);
				printf("\tformat_str=%s\n",format_str);
				sscanf(buffer+pos,format_str,p_drawing_info->text,&ch_consumed);
				printf("\tp_drawing_info->text=%s\n",p_drawing_info->text);
				printf("\tch_consumed=%u\n",ch_consumed);
				pos+=ch_consumed;
				break;
			}
			case 'F':
			{
				//F s n -c1c2...cn
				//Set font. The font size is s points. The font name consists of the n characters following '-'. (1.1)
				sscanf(buffer+pos," %f %u%n",&p_drawing_info->size,&n,&ch_consumed);
				//char size[100];
				//sscanf(buffer+pos," %s %u%n",size,&n,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<n || n<0)
					break;				

				p_drawing_info->text=(char *)malloc(sizeof(char)*(n+1));
				memset(p_drawing_info->text,0,n+1);
				char format_str[20];
				_snprintf(format_str,sizeof(format_str)," -%%%uc%%n",n);
				printf("\tformat_str=%s\n",format_str);
				sscanf(buffer+pos,format_str,p_drawing_info->text,&ch_consumed);
				printf("\tp_drawing_info->text=%s\n",p_drawing_info->text);
				pos+=ch_consumed;
				break;
			}
			case 'S':
			{
				//S n -c1c2...cn
				//Set style attribute. The style value consists of the n characters following '-'. The syntax of the value is the same as specified for a styleItem in style. (1.1)  
				sscanf(buffer+pos," %u%n",&n,&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<n || n<0)
					break;				

				p_drawing_info->text=(char *)malloc(sizeof(char)*(n+1));
				memset(p_drawing_info->text,0,n+1);
				char format_str[20];
				_snprintf(format_str,sizeof(format_str)," -%%%uc%%n",n);
				printf("\tformat_str=%s\n",format_str);
				sscanf(buffer+pos,format_str,p_drawing_info->text,&ch_consumed);
				printf("\tp_drawing_info->text=%s\n",p_drawing_info->text);
				pos+=ch_consumed;
				break;
			}
			case 'I':
			{
				//I x y w h n -c1c2...cn
				//Externally-specified image drawn in the box with lower left corner (x,y) and upper right corner (x+w,y+h). The name of the image consists of the n characters following '-'. This is usually a bitmap image. Note that the image size, even when converted from pixels to points, might be different from the required size (w,h). It is assumed the renderer will perform the necessary scaling. (1.2)
				p_drawing_info->count=2;
				p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);				
				sscanf(buffer+pos," %u %u %u %u %u%n",
					&p_drawing_info->points[0].x,
					&p_drawing_info->points[0].y,
					&p_drawing_info->points[1].y, //j
					&p_drawing_info->points[1].x,
					&n,
					&ch_consumed);
				pos+=ch_consumed;
				if(MAX_SIZE<n || n<0)
					break;				
				p_drawing_info->text=(char *)malloc(sizeof(char)*(n+1));
				memset(p_drawing_info->text,0,n+1);
				char format_str[20];
				_snprintf(format_str,sizeof(format_str)," -%%%uc%%n",n);
				printf("\tformat_str=%s\n",format_str);
				sscanf(buffer+pos,format_str,p_drawing_info->text,&ch_consumed);
				printf("\tp_drawing_info->text=%s\n",p_drawing_info->text);
				pos+=ch_consumed;
				break;
			}
			default:
				is_valid_type=FALSE;
				break;
		}
		if(is_valid_type)
		{
			p_drawing_infos->push_back(p_drawing_info);
		}		
		while(buffer[pos]==' ' && buffer[pos]!=NULL)
		{
			pos++;
		}
		if(!is_valid_type)
			break;
	}
	return p_drawing_infos;
}

void CGraphVizProcessor::DumpNodeInfo(Agnode_t *n)
{	
	int i;
	
	printf("==================\n");
	for(i=0;
		i<dtsize(n->graph->univ->nodeattr->dict);
		i++)
	{
		printf("node: %s-%s\n",
			n->graph->univ->nodeattr->list[i]->name,
			agxget(n,n->graph->univ->nodeattr->list[i]->index));
	}
}

void CGraphVizProcessor::DumpEdgeInfo(Agedge_t *e)
{
	int i;
	
	printf("==================\n");
	for(i=0;
		i<dtsize(e->tail->graph->univ->edgeattr->dict);
		i++)
	{
		printf("edge: %s-%s\n",
			e->tail->graph->univ->edgeattr->list[i]->name,
			agxget(e,e->tail->graph->univ->edgeattr->list[i]->index));
	}
}

char *CGraphVizProcessor::GetGraphAttribute(Agraph_t *g,char *attr)
{
	char *val;
	Agsym_t *a;
	a=agfindattr(g->root,attr);
	if (!a)
		return "";
	val=agxget(g, a->index);
	if(!val)
		return "";
	return val;
}

char *CGraphVizProcessor::GetNodeAttribute(Agnode_t *n, char *attr)
{
	Agraph_t *g;
	Agsym_t *a;
	char *val;

	g=n->graph->root;

	a=agfindattr(g->proto->n,attr);
	if (!a)
		return "";
	val=agxget(n,a->index);
	if (!val)
		return "";
	return val;
}

char *CGraphVizProcessor::GetEdgeAttribute(Agedge_t *e, char *attr)
{
	Agraph_t *g;
	Agsym_t *a;
	char *val;

	g=e->head->graph->root;

	a=agfindattr(g->proto->e,attr);
	if (!a)
		return "";
	val=agxget(e,a->index);
	if (!val)
		return "";
	return val;
}

void CGraphVizProcessor::GetDrawingInfo(DWORD address,list<DrawingInfo *> *p_drawing_info_map,BYTE type,char *str)
{
	if(type==TYPE_DI_FILLCOLOR || type==TYPE_DI_COLOR || type==TYPE_DI_BGCOLOR || type==TYPE_DI_FONTCOLOR)
	{
		if(type==TYPE_DI_FONTCOLOR)
		{
			if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("%s: [fontcolor] set %s\n",__FUNCTION__,str);
		}
		if(type==TYPE_DI_FILLCOLOR)
		{
			if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("%s: [fillcolor] set %s\n",__FUNCTION__,str);
		}
		DrawingInfo *p_drawing_info=(DrawingInfo *)malloc(sizeof(DrawingInfo));
		p_drawing_info->address=address;
		p_drawing_info->type=type;
		p_drawing_info->points=NULL;
		p_drawing_info->count=0;
		p_drawing_info->text=strdup(str);
		p_drawing_info_map->push_back(p_drawing_info);
	}else if(type==TYPE_DI_RECTS)
	{
		DrawingInfo *p_drawing_info=(DrawingInfo *)malloc(sizeof(DrawingInfo));
		p_drawing_info->address=address;
		p_drawing_info->type=type;
		p_drawing_info->points=NULL;
		p_drawing_info->count=0;
		p_drawing_info->text=NULL;
		for(DWORD i=0;i<strlen(str);i++)
		{
			if(i==0 || str[i-1]==' ')
			{
				int x1,y1,x2,y2;
				sscanf((const char *)str+i,"%u,%u,%u,%u",&x1,&y1,&x2,&y2);
				p_drawing_info->count+=2;
			}
		}
		p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
		int pos=0;
		for(DWORD i=0;i<strlen(str);i++)
		{
			if(i==0 || str[i-1]==' ')
			{
				sscanf((const char *)str+i,"%u,%u,%u,%u",
					&p_drawing_info->points[pos].x,
					&p_drawing_info->points[pos].y,
					&p_drawing_info->points[pos+1].x,
					&p_drawing_info->points[pos+1].y);
				pos+=2;
			}
		}
		p_drawing_info_map->push_back(p_drawing_info);
	}else if(type==TYPE_DI_DRAW)
	{
		/*
		_ldraw_=c 5 -black F 14.000000 11 -Times-Roman T 1295 379 0 69 10 -0x77d529c8 
				c 5 -black F 14.000000 11 -Times-Roman T 1295 355 0 177 25 -_ObjectFromDIBResource@24 
				c 5 -black F 14.000000 11 -Times-Roman T 1295 331 0 250 41 -call _pfnLockResource; _LockResource(x,x)
		*/
		list <DrawingInfo *>::iterator drawing_info_iterator;
		list <DrawingInfo *> *ret=ParseXDOTAttributeString(str);
		for(drawing_info_iterator=ret->begin();
			drawing_info_iterator!=ret->end();
			drawing_info_iterator++)
		{
			DrawingInfo *p_drawing_info=*drawing_info_iterator;
			p_drawing_info->address=address;
			p_drawing_info->type=type;	
			p_drawing_info_map->push_back(p_drawing_info);
		}
		delete ret;
	}
}

int CGraphVizProcessor::RenderToFile(char *format,char *filename)
{
	GVC_t *gvc;

	/* set up a graphviz context */
	gvc=gvContext();
	/* parse command line args - minimally argv[0] sets layout engine */
	//gvParseArgs(gvc,argc,argv);
	/* Compute a layout using layout engine from command line args */
	//gvLayoutJobs(gvc, g);
	/* Write the graph according to -T and -o options */
	//gvRenderJobs(gvc, g);
	agsafeset(g,"charset","Latin1","");
	gvLayout(gvc,g,"dot");	

	return gvRenderFilename(gvc,g,format,filename);
}

list<DrawingInfo *> *CGraphVizProcessor::GenerateDrawingInfo()
{
	Agnode_t *n;
	GVC_t *gvc;
	list<DrawingInfo *> *DrawingInfoMap=new list<DrawingInfo *>;

	/* set up a graphviz context */
	gvc=gvContext();
	/* parse command line args - minimally argv[0] sets layout engine */
	//gvParseArgs(gvc,argc,argv);

	////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////	
	/* Compute a layout using layout engine from command line args */
	//gvLayoutJobs(gvc, g);
	/* Write the graph according to -T and -o options */
	//gvRenderJobs(gvc, g);
	agsafeset(g,"charset","Latin1","");
#ifdef TEST
	agsafeset(g,"mode","hier","");
	gvLayout(gvc,g,"neato");
#else
	printf("calling gvLayout\n");
	gvLayout(gvc,g,"dot");	
	printf("gvLayout\n");
#endif

	//gvRenderFilename(gvc,g,"xdot","test.xdot");
	//gvRenderFilename(gvc,g,"gif","test.gif");
	gvRender(gvc,g,"xdot",NULL);
	if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("gvRender\n");

	if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("bb=%s\n",GetGraphAttribute(g,"bb"));
	if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("_draw_=%s\n",GetGraphAttribute(g,"_draw_"));
	DrawingInfo *p_drawing_info=(DrawingInfo *)malloc(sizeof(DrawingInfo));
	p_drawing_info->type=TYPE_DI_GRAPH;
	p_drawing_info->count=2;
	p_drawing_info->points=(POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
	float pos[4];
	sscanf(GetGraphAttribute(g,"bb")," %f,%f,%f,%f",&pos[0],&pos[1],&pos[2],&pos[3]);
	p_drawing_info->points[0].x=(int)pos[0];
	p_drawing_info->points[0].y=(int)pos[1];
	p_drawing_info->points[1].x=(int)pos[2];
	p_drawing_info->points[1].y=(int)pos[3];
	p_drawing_info->text=NULL;
	p_drawing_info->address=0;
	DrawingInfoMap->push_back(p_drawing_info);

	for(n=agfstnode(g);n;n=agnxtnode(g,n))
	{
		DWORD address=NodeToUserDataMap->find(n)->second;
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("name=%s\n",n->name);
		/*
		digraph g {
			graph 
			[
				bb="0,0,86,180",
				_draw_="c 5 -white C 5 -white P 4 0 0 0 180 86 180 86 0 ",
				xdotversion="1.1"
			];
			"{0xff00ff00|TestFunc@1|xxxx}" [
				label="{0xff00ff00|TestFunc@1|xxxx}",
				color=blue,
				shape=record,
				pos="43,144",rects="0,156,86,180 0,132,86,156 0,108,86,132",
				width="1.19",
				height="1.00",
				_draw_="c 4 -blue p 4 0 108 0 180 86 180 86 108 c 4 -blue L 2 0 156 86 156 c 4 -blue L 2 0 132 86 132 ",
				_ldraw_="F 14.000000 11 -Times-Roman c 5 -black T 43 162 0 59 10 -0xff00ff00 F 14.000000 11 -Times-Roman c 5 -black T 43 138 0 70 10 -Tes\
				tFunc@1 F 14.000000 11 -Times-Roman c 5 -black T 43 114 0 29 4 -xxxx "
			];
			t2 [
				label="{0xff00ff00|TestFunc@1|xxxx}",
				color=blue,
				shape=record,
				pos="43,36",rects="0,48,86,72 0,24,86,48 0,0,86,24",
				width="1.19",
				height="1.00",
				_draw_="c 4 -blue p 4 0 0 0 72 86 72 86 0 c 4 -blue L 2 0 48 86 48 c 4 -blue L 2 0 24 86 24 ",
				_ldraw_="F 14.000000 11 -Times-Roman c 5 -black T 43 54 0 59 10 -0xff00ff00 F 14.000000 11 -Times-Roman c 5 -black T 43 30 0 70 10 -TestF\
				unc@1 F 14.000000 11 -Times-Roman c 5 -black T 43 6 0 29 4 -xxxx "
			];
			"{0xff00ff00|TestFunc@1|xxxx}" -> t2 [
				pos="e,43,72 43,108 43,99 43,91 43,82",
				_draw_="c 5 -black B 4 43 108 43 99 43 91 43 82 ",
				_hdraw_="S 5 -solid S 15 -setlinewidth(1) c 5 -black C 5 -black P 3 47 82 43 72 40 82 "
			];
		}
		*/
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("shape=%s\n",GetNodeAttribute(n,"shape"));
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("color=%s\n",GetNodeAttribute(n,"color"));
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("pos=%s\n",GetNodeAttribute(n,"pos"));
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("width=%s\n",GetNodeAttribute(n,"width"));
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("height=%s\n",GetNodeAttribute(n,"height"));

		//_draw_
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("rects=%s\n",GetNodeAttribute(n,"rects"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_COLOR,GetNodeAttribute(n,"color"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_FILLCOLOR,GetNodeAttribute(n,"fillcolor"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_BGCOLOR,GetNodeAttribute(n,"bgcolor"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_FONTCOLOR,GetNodeAttribute(n,"fontcolor"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_RECTS,GetNodeAttribute(n,"rects"));
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("_draw_=%s\n",GetNodeAttribute(n,"_draw_"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_DRAW,GetNodeAttribute(n,"_draw_"));
		if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("_ldraw_=%s\n",GetNodeAttribute(n,"_ldraw_"));
		GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_DRAW,GetNodeAttribute(n,"_ldraw_"));

		Agedge_t *e;
		for(e=agfstedge(g,n);e;
			e=agnxtedge(g,e,n)
		)
		{
			GetEdgeAttribute(e,"pos");
			GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_DRAW,GetEdgeAttribute(e,"_draw_"));
			GetDrawingInfo(address,DrawingInfoMap,TYPE_DI_DRAW,GetEdgeAttribute(e,"_hdraw_"));
			for(int i=0;
				i<dtsize(e->tail->graph->univ->edgeattr->dict);
				i++)
			{
				if(GraphVizInterfaceProcessorDebugLevel>0) if(GraphVizInterfaceProcessorDebugLevel>0) dprintf("edge: %s-%s\n",
					e->tail->graph->univ->edgeattr->list[i]->name,
					agxget(e,e->tail->graph->univ->edgeattr->list[i]->index));
			}
		}
	}

	/* Free layout data */
	gvFreeLayout(gvc,g);
	/* Free graph structures */
	agclose(g);
	/* close output file, free context, and return number of errors */
	gvFreeContext(gvc);
	return DrawingInfoMap;
}

