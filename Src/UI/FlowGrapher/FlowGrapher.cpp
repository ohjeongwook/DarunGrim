#pragma warning(disable:4005)
#pragma warning(disable:4996)
#include "FlowGrapher.h"
#include <gvc.h>

using namespace std;

#define MAX_SIZE 1000

FlowGrapher::FlowGrapher() : FontColor(NULL), FillColor(NULL), FontName(NULL), FontSize("18"), Debug(0)
{
	DrawingObjectList = new vector<DrawingInfo *>;

	gvc = gvContext();
	g = agopen("g", AGDIGRAPH);

	NodeToUserDataMap = new stdext::hash_map<Agnode_t *, DWORD>;
}

FlowGrapher::~FlowGrapher()
{
	agclose(g);
	gvFreeContext(gvc); //Disabled due to unknown crashes
	delete NodeToUserDataMap;
}

char *EscapeString(char *src)
{
	//<>{}|
	int src_len = strlen(src);
	char *dst = (char *)malloc(strlen(src) * 2 + 1);
	int j = 0;
	for (int i = 0; i<src_len + 1; i++, j++)
	{
		if (src[i] == '<' || src[i] == '>' || src[i] == '{' || src[i] == '}' || src[i] == '|')
		{
			dst[j] = '\\';
			j++;
			dst[j] = src[i];
		}
		else
		{
			dst[j] = src[i];
		}
	}
	return dst;
}

void FlowGrapher::SetNodeShape(char *fontcolor, char *fillcolor, char *fontname, char *fontsize)
{
	FontColor = fontcolor;
	FillColor = fillcolor;
	FontName = fontname;
	FontSize = fontsize;
}

void FlowGrapher::AddNode(DWORD node_id, LPCSTR node_name, LPCSTR node_data)
{

	Agnode_t *n;
	char name[1024 * 4];
	char *escaped_node_name = EscapeString((char *)node_name);
	char *escaped_node_data = EscapeString((char *)node_data);

	_snprintf(name, sizeof(name),
		"{%s|%s}",
		escaped_node_name,
		escaped_node_data);
	n = agnode(g, name);
	agsafeset(n, "label", name, "");
	if (node_data)
		agsafeset(n, "shape", "record", "");
	else
		agsafeset(n, "shape", "rect", "");

	agsafeset(n, "fontname", FontName, "");
	agsafeset(n, "fontsize", FontSize, "");
	if (FontColor)
	{
		if (Debug>0)
			dprintf("%s: [fontcolor] set to [%s]\n", __FUNCTION__, FontColor);
		agsafeset(n, "fontcolor", FontColor, "");
	}
	if (FillColor)
	{
		agsafeset(n, "style", "filled", "");
		if (Debug>0)
			dprintf("%s: node_name=%s [fillcolor] set to [%s]\n", __FUNCTION__, node_name, FillColor);
		agsafeset(n, "fillcolor", FillColor, "");
	}
	AddressToNodeMap.insert(std::pair <DWORD, Agnode_t *>(node_id, n));
	NodeToUserDataMap->insert(std::pair <Agnode_t *, DWORD>(n, node_id));
	free(escaped_node_name);
	free(escaped_node_data);
}

void FlowGrapher::AddLink(DWORD src, DWORD dst)
{
	Agedge_t *e;
	stdext::hash_map<DWORD, Agnode_t *>::iterator it;
	Agnode_t *src_node = NULL;
	Agnode_t *dst_node = NULL;

	it = AddressToNodeMap.find(src);
	if (it != AddressToNodeMap.end())
	{
		src_node = it->second;
	}

	it = AddressToNodeMap.find(dst);
	if (it != AddressToNodeMap.end())
	{
		dst_node = it->second;
	}

	if (src_node && dst_node)
	{
		e = agedge(g, src_node, dst_node);
	}

	return;
}

vector <DrawingInfo *> *FlowGrapher::ParseXDOTAttributeString(char *buffer)
{
	int pos = 0;
	int ch_consumed;
	int n;
	int i;
	vector <DrawingInfo *> *p_drawing_infos = new vector <DrawingInfo *>;

	if (Debug>0)
		dprintf("%s\n", buffer);

	while (buffer[pos])
	{
		bool is_valid_type = TRUE;
		DrawingInfo *p_drawing_info = (DrawingInfo *)malloc(sizeof(DrawingInfo));
		memset(p_drawing_info, 0, sizeof(DrawingInfo));
		sscanf(buffer + pos, "%c%n", &p_drawing_info->subtype, &ch_consumed);
		pos += ch_consumed;

		if (Debug > 0)
			dprintf("Type is [%c]\n", p_drawing_info->subtype);

		switch (p_drawing_info->subtype)
		{
		case 'E':
		{
					//E point_x point_y w h
					//Filled ellipse ((x-point_x)/w)2 + ((y-point_y)/h)2 = 1
					p_drawing_info->count = 2;
					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					sscanf(buffer + pos, " %u %u %u %u%n", &p_drawing_info->points[0].x, &p_drawing_info->points[0].y, &p_drawing_info->points[1].x, &p_drawing_info->points[1].y, &ch_consumed);
					pos += ch_consumed;
					break;
		}
		case 'e':
		{
					//e point_x point_y w h
					//Unfilled ellipse ((x-point_x)/w)2 + ((y-point_y)/h)2 = 1 
					p_drawing_info->count = 2;
					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					sscanf(buffer + pos, " %u %u %u %u%n", &p_drawing_info->points[0].x, &p_drawing_info->points[0].y, &p_drawing_info->points[1].x, &p_drawing_info->points[1].y, &ch_consumed);
					pos += ch_consumed;
					break;
		}
		case 'P':
		{
					//P n x1 y1 ... xn yn
					//Filled polygon using the given n points
					sscanf(buffer + pos, " %u%n", &p_drawing_info->count, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
						break;
					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					for (i = 0; i<p_drawing_info->count; i++)
					{
						sscanf(buffer + pos, " %u %u%n", &p_drawing_info->points[i].x, &p_drawing_info->points[i].y, &ch_consumed);
						pos += ch_consumed;
					}
					break;
		}
		case 'p':
		{
					//p n x1 y1 ... xn yn
					//Unfilled polygon using the given n points
					sscanf(buffer + pos, " %u%n", &p_drawing_info->count, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
						break;

					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					for (i = 0; i<p_drawing_info->count; i++)
					{
						sscanf(buffer + pos, " %u %u%n", &p_drawing_info->points[i].x, &p_drawing_info->points[i].y, &ch_consumed);
						pos += ch_consumed;
					}
					break;
		}
		case 'L':
		{
					//L n x1 y1 ... xn yn
					//Polyline using the given n points
					sscanf(buffer + pos, " %u%n", &p_drawing_info->count, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
						break;

					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					for (i = 0; i<p_drawing_info->count; i++)
					{
						sscanf(buffer + pos, " %u %u%n", &p_drawing_info->points[i].x, &p_drawing_info->points[i].y, &ch_consumed);
						pos += ch_consumed;
					}
					break;
		}
		case 'B':
		{
					//B n x1 y1 ... xn yn
					//B-spline using the given n control points
					sscanf(buffer + pos, " %u%n", &p_drawing_info->count, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
						break;

					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					for (i = 0; i<p_drawing_info->count; i++)
					{
						sscanf(buffer + pos, " %u %u%n", &p_drawing_info->points[i].x, &p_drawing_info->points[i].y, &ch_consumed);
						pos += ch_consumed;
					}
					break;
		}
		case 'b':
		{
					//b n x1 y1 ... xn yn
					//Filled B-spline using the given n control points (1.1)
					sscanf(buffer + pos, " %u%n", &p_drawing_info->count, &ch_consumed);
					pos += ch_consumed;

					if (Debug > 0)
						dprintf("\tp_drawing_info->count=%u\n", p_drawing_info->count);

					if (MAX_SIZE<p_drawing_info->count || p_drawing_info->count<0)
						break;

					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					for (i = 0; i<p_drawing_info->count; i++)
					{
						sscanf(buffer + pos, " %u %u%n", &p_drawing_info->points[i].x, &p_drawing_info->points[i].y, &ch_consumed);
						pos += ch_consumed;
					}
					break;
		}
		case 'T':
		{
					//T x y j w n -c1c2...cn
					//Text drawn using the baseline point (x,y). The text consists of the n characters following '-'. 
					//The text should be left-aligned (centered, right-aligned) on the point if j is -1 (0, 1), 
					//respectively. The value w gives the width of the text as computed by the library.
					p_drawing_info->count = 2;
					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					sscanf(buffer + pos, " %u %u %u %u %u%n",
						&p_drawing_info->points[0].x,
						&p_drawing_info->points[0].y,
						&p_drawing_info->points[1].y, //j
						&p_drawing_info->points[1].x, //w
						&n,
						&ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<n || n<0)
						break;

					p_drawing_info->text = (char *)malloc(sizeof(char)*(n + 2));
					memset(p_drawing_info->text, 0, n + 2);
					char format_str[20];
					_snprintf(format_str, sizeof(format_str), " -%%%uc%%n", n);
					sscanf(buffer + pos, format_str, p_drawing_info->text, &ch_consumed);
					pos += ch_consumed;
					break;
		}
		case 'C':
		{
					//C n -c1c2...cn
					//Set fill color. The color value consists of the n characters following '-'. (1.1)
					sscanf(buffer + pos, " %u%n", &n, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<n || n<0)
						break;

					p_drawing_info->text = (char *)malloc(sizeof(char)*(n + 1));
					memset(p_drawing_info->text, 0, n + 1);
					char format_str[20];
					_snprintf(format_str, sizeof(format_str), " -%%%uc%%n", n);

					if (Debug > 0)
						dprintf("\tformat_str=%s\n", format_str);

					sscanf(buffer + pos, format_str, p_drawing_info->text, &ch_consumed);

					if (Debug > 0)
						dprintf("\tp_drawing_info->text=%s\n", p_drawing_info->text);

					pos += ch_consumed;
					break;
		}
		case 'c':
		{
					//c n -c1c2...cn
					//Set pen color. The color value consists of the n characters following '-'. (1.1)
					sscanf(buffer + pos, " %u%n", &n, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE < n || n<0)
						break;

					if (Debug > 0)
						dprintf("\tn=%u\n", n);

					p_drawing_info->text = (char *)malloc(sizeof(char)*(n + 1));
					memset(p_drawing_info->text, 0, n + 1);

					char format_str[20];
					_snprintf(format_str, sizeof(format_str), " -%%%uc%%n", n);

					if (Debug > 0)
						dprintf("\tformat_str=%s\n", format_str);

					sscanf(buffer + pos, format_str, p_drawing_info->text, &ch_consumed);

					if (Debug > 0)
					{
						dprintf("\tp_drawing_info->text=%s\n", p_drawing_info->text);
						dprintf("\tch_consumed=%u\n", ch_consumed);
					}

					pos += ch_consumed;
					break;
		}
		case 'F':
		{
					//F s n -c1c2...cn
					//Set font. The font size is s points. The font name consists of the n characters following '-'. (1.1)

					sscanf(buffer + pos, " %f %u%n", &p_drawing_info->size, &n, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<n || n<0)
						break;

					p_drawing_info->text = (char *)malloc(sizeof(char)*(n + 1));
					memset(p_drawing_info->text, 0, n + 1);

					char format_str[20];
					_snprintf(format_str, sizeof(format_str), " -%%%uc%%n", n);

					if (Debug > 0)
						dprintf("\tformat_str=%s\n", format_str);

					sscanf(buffer + pos, format_str, p_drawing_info->text, &ch_consumed);

					if (Debug > 0)
						dprintf("\tp_drawing_info->text=%s\n", p_drawing_info->text);

					pos += ch_consumed;
					break;
		}
		case 'S':
		{
					//S n -c1c2...cn
					//Set style attribute. The style value consists of the n characters following '-'. The syntax of the value is the same as specified for a styleItem in style. (1.1)  
					sscanf(buffer + pos, " %u%n", &n, &ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<n || n<0)
						break;

					p_drawing_info->text = (char *)malloc(sizeof(char)*(n + 1));
					memset(p_drawing_info->text, 0, n + 1);
					char format_str[20];
					_snprintf(format_str, sizeof(format_str), " -%%%uc%%n", n);
					
					if (Debug > 0)
						dprintf("\tformat_str=%s\n", format_str);
					sscanf(buffer + pos, format_str, p_drawing_info->text, &ch_consumed);

					if (Debug > 0)
						dprintf("\tp_drawing_info->text=%s\n", p_drawing_info->text);
					pos += ch_consumed;
					break;
		}
		case 'I':
		{
					//I x y w h n -c1c2...cn
					//Externally-specified image drawn in the box with lower left corner (x,y) and upper right corner (x+w,y+h). The name of the image consists of the n characters following '-'. This is usually a bitmap image. Note that the image size, even when converted from pixels to points, might be different from the required size (w,h). It is assumed the renderer will perform the necessary scaling. (1.2)
					p_drawing_info->count = 2;
					p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
					sscanf(buffer + pos, " %u %u %u %u %u%n",
						&p_drawing_info->points[0].x,
						&p_drawing_info->points[0].y,
						&p_drawing_info->points[1].y, //j
						&p_drawing_info->points[1].x,
						&n,
						&ch_consumed);
					pos += ch_consumed;
					if (MAX_SIZE<n || n<0)
						break;
					p_drawing_info->text = (char *)malloc(sizeof(char)*(n + 1));
					memset(p_drawing_info->text, 0, n + 1);
					char format_str[20];
					_snprintf(format_str, sizeof(format_str), " -%%%uc%%n", n);
					
					if (Debug > 0)
						dprintf("\tformat_str=%s\n", format_str);
					sscanf(buffer + pos, format_str, p_drawing_info->text, &ch_consumed);
					
					if (Debug > 0)
						dprintf("\tp_drawing_info->text=%s\n", p_drawing_info->text);
					pos += ch_consumed;
					break;
		}
		default:
			is_valid_type = FALSE;
			break;
		}
		if (is_valid_type)
		{
			p_drawing_infos->push_back(p_drawing_info);
		}
		while (buffer[pos] == ' ' && buffer[pos] != NULL)
		{
			pos++;
		}
		if (!is_valid_type)
			break;
	}
	return p_drawing_infos;
}

void FlowGrapher::DumpNodeInfo(Agnode_t *n)
{
	int i;

	dprintf("==================\n");
	for (i = 0;
		i<dtsize(n->graph->univ->nodeattr->dict);
		i++)
	{
		dprintf("node: %s-%s\n",
			n->graph->univ->nodeattr->list[i]->name,
			agxget(n, n->graph->univ->nodeattr->list[i]->index));
	}
}

void FlowGrapher::DumpEdgeInfo(Agedge_t *e)
{
	int i;

	dprintf("==================\n");
	for (i = 0;
		i<dtsize(e->tail->graph->univ->edgeattr->dict);
		i++)
	{
		dprintf("edge: %s-%s\n",
			e->tail->graph->univ->edgeattr->list[i]->name,
			agxget(e, e->tail->graph->univ->edgeattr->list[i]->index));
	}
}

char *FlowGrapher::GetGraphAttribute(Agraph_t *g, char *attr)
{
	char *val;
	Agsym_t *a;
	a = agfindattr(g->root, attr);
	if (!a)
		return "";
	val = agxget(g, a->index);
	if (!val)
		return "";
	return val;
}

char *FlowGrapher::GetNodeAttribute(Agnode_t *n, char *attr)
{
	Agraph_t *g;
	Agsym_t *a;
	char *val;

	g = n->graph->root;

	a = agfindattr(g->proto->n, attr);

	if (!a)
		return "";

	val = agxget(n, a->index);

	if (!val)
		return "";

	return val;
}

char *FlowGrapher::GetEdgeAttribute(Agedge_t *e, char *attr)
{
	Agraph_t *g;
	Agsym_t *a;
	char *val;

	g = e->head->graph->root;

	a = agfindattr(g->proto->e, attr);
	if (!a)
		return "";
	val = agxget(e, a->index);
	if (!val)
		return "";
	return val;
}

void FlowGrapher::AddDrawingInfo(DWORD address, vector<DrawingInfo *> *p_drawing_info_map, BYTE type, char *str)
{
	if (type == TYPE_DI_FILLCOLOR || type == TYPE_DI_COLOR || type == TYPE_DI_BGCOLOR || type == TYPE_DI_FONTCOLOR)
	{
		DrawingInfo *p_drawing_info = (DrawingInfo *)malloc(sizeof(DrawingInfo));
		p_drawing_info->address = address;
		p_drawing_info->type = type;
		p_drawing_info->points = NULL;
		p_drawing_info->count = 0;
		p_drawing_info->text = strdup(str);
		p_drawing_info_map->push_back(p_drawing_info);
	}
	else if (type == TYPE_DI_RECTS)
	{
		DrawingInfo *p_drawing_info = (DrawingInfo *)malloc(sizeof(DrawingInfo));
		p_drawing_info->address = address;
		p_drawing_info->type = type;
		p_drawing_info->points = NULL;
		p_drawing_info->count = 0;
		p_drawing_info->text = NULL;

		if (Debug > 0)
			dprintf("* TYPE_DI_RECTS: %s\n", str);

		for (DWORD i = 0; i<strlen(str); i++)
		{
			if (i == 0 || str[i - 1] == ' ')
			{
				float x1, y1, x2, y2;
				sscanf((const char *)str + i, "%f,%f,%f,%f", &x1, &y1, &x2, &y2);

				if (Debug > 0)
					dprintf("	%f,%f,%f,%f\n", x1, y1, x2, y2);

				p_drawing_info->count += 2;
			}
		}

		p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
		int pos = 0;
		for (DWORD i = 0; i<strlen(str); i++)
		{
			if (i == 0 || str[i - 1] == ' ')
			{
				float x1, y1, x2, y2;
				sscanf((const char *)str + i, "%f,%f,%f,%f", &x1, &y1, &x2, &y2);

				p_drawing_info->points[pos].x = x1;
				p_drawing_info->points[pos].y = y1;
				p_drawing_info->points[pos + 1].x = x2;
				p_drawing_info->points[pos + 1].y = y2;

				if (Debug > 0)
					dprintf("	%u,%u,%u,%u\n",
						p_drawing_info->points[pos].x,
						p_drawing_info->points[pos].y,
						p_drawing_info->points[pos + 1].x,
						p_drawing_info->points[pos + 1].y);
				pos += 2;
			}
		}
		p_drawing_info_map->push_back(p_drawing_info);
	}
	else if (type == TYPE_DI_DRAW)
	{
		/*
		_ldraw_=c 5 -black F 14.000000 11 -Times-Roman T 1295 379 0 69 10 -0x77d529c8
		c 5 -black F 14.000000 11 -Times-Roman T 1295 355 0 177 25 -_ObjectFromDIBResource@24
		c 5 -black F 14.000000 11 -Times-Roman T 1295 331 0 250 41 -call _pfnLockResource; _LockResource(x,x)
		*/
		vector <DrawingInfo *>::iterator drawing_info_iterator;
		vector <DrawingInfo *> *ret = ParseXDOTAttributeString(str);
		for (drawing_info_iterator = ret->begin();
			drawing_info_iterator != ret->end();
			drawing_info_iterator++)
		{
			DrawingInfo *p_drawing_info = *drawing_info_iterator;
			p_drawing_info->address = address;
			p_drawing_info->type = type;
			p_drawing_info_map->push_back(p_drawing_info);
		}
		delete ret;
	}
}

int FlowGrapher::RenderToFile(char *format, char *filename)
{
	gvLayoutJobs(gvc, g);
	gvRenderJobs(gvc, g);
	agsafeset(g, "charset", "Latin1", "");
	gvLayout(gvc, g, "dot");

	return gvRenderFilename(gvc, g, format, filename);
}

void FlowGrapher::GenerateDrawingInfo()
{
	DrawingObjectList->clear();

	gvLayoutJobs(gvc, g);
	gvRenderJobs(gvc, g);

	agsafeset(g, "charset", "Latin1", "");

	try
	{
		gvLayout(gvc, g, "dot");
	}
	catch (...)
	{
	}

	try
	{
		gvRender(gvc, g, "xdot", NULL);
	}
	catch (...)
	{
		return;
	}

	if (Debug > 0)
	{
		dprintf("gvRender\n");
		dprintf("bb=%s\n", GetGraphAttribute(g, "bb"));
		dprintf("_draw_=%s\n", GetGraphAttribute(g, "_draw_"));
	}

	DrawingInfo *p_drawing_info = (DrawingInfo *)malloc(sizeof(DrawingInfo));
	p_drawing_info->type = TYPE_DI_GRAPH;
	p_drawing_info->count = 2;
	p_drawing_info->points = (POINT *)malloc(sizeof(POINT)*p_drawing_info->count);
	float pos[4];
	sscanf(GetGraphAttribute(g, "bb"), " %f,%f,%f,%f", &pos[0], &pos[1], &pos[2], &pos[3]);
	p_drawing_info->points[0].x = (int)pos[0];
	p_drawing_info->points[0].y = (int)pos[1];
	p_drawing_info->points[1].x = (int)pos[2];
	p_drawing_info->points[1].y = (int)pos[3];
	p_drawing_info->text = NULL;
	p_drawing_info->address = 0;
	DrawingObjectList->push_back(p_drawing_info);

	for (Agnode_t *n = agfstnode(g); n; n = agnxtnode(g, n))
	{
		DWORD address = NodeToUserDataMap->find(n)->second;

		if (Debug > 0)
		{
			char *name = n->name;
			char *width = GetNodeAttribute(n, "width");
			char *height = GetNodeAttribute(n, "height");
			
			dprintf("name=%s\n", name);
			dprintf("width=%s\n", width);
			dprintf("height=%s\n", height);

			dprintf("shape=%s\n", GetNodeAttribute(n, "shape"));
			dprintf("color=%s\n", GetNodeAttribute(n, "color"));
			dprintf("pos=%s\n", GetNodeAttribute(n, "pos"));
			dprintf("rects=%s\n", GetNodeAttribute(n, "rects"));
			dprintf("_draw_=%s\n", GetNodeAttribute(n, "_draw_"));
			dprintf("_ldraw_=%s\n", GetNodeAttribute(n, "_ldraw_"));
		}

		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_COLOR, GetNodeAttribute(n, "color"));
		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_FILLCOLOR, GetNodeAttribute(n, "fillcolor"));
		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_BGCOLOR, GetNodeAttribute(n, "bgcolor"));
		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_FONTCOLOR, GetNodeAttribute(n, "fontcolor"));
		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_RECTS, GetNodeAttribute(n, "rects"));
		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_DRAW, GetNodeAttribute(n, "_draw_"));
		AddDrawingInfo(address, DrawingObjectList, TYPE_DI_DRAW, GetNodeAttribute(n, "_ldraw_"));

		for (Agedge_t *e = agfstedge(g, n); e; e = agnxtedge(g, e, n))
		{
			GetEdgeAttribute(e, "pos");
			AddDrawingInfo(address, DrawingObjectList, TYPE_DI_DRAW, GetEdgeAttribute(e, "_draw_"));
			AddDrawingInfo(address, DrawingObjectList, TYPE_DI_DRAW, GetEdgeAttribute(e, "_hdraw_"));

			for (int i = 0;
				i<dtsize(e->tail->graph->univ->edgeattr->dict);
				i++)
			{
				if (Debug>0) 
					dprintf("edge: %s-%s\n",
						e->tail->graph->univ->edgeattr->list[i]->name,
						agxget(e, e->tail->graph->univ->edgeattr->list[i]->index));
			}
		}
	}
	gvFreeLayout(gvc, g);
}

vector<DrawingInfo *> *FlowGrapher::GetDrawingInfo()
{
	return DrawingObjectList;
}

int FlowGrapher::GetDrawingInfoLength()
{
	return DrawingObjectList->size();
}

DrawingInfo *FlowGrapher::GetDrawingInfoMember(int i)
{
	return DrawingObjectList->at(i);
}