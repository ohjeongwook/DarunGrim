/* File : FlowGrapher.i */
%module FlowGrapher
%include typemaps.i

%{
#include <windows.h>
#include "FlowGrapher.h"
%}

%inline %{
typedef unsigned long DWORD;
typedef unsigned char BYTE;
%}

typedef struct {
	int x;
	int y;
} POINT;

typedef struct _DrawingInfo_{
	DWORD address;
	BYTE type;
	BYTE subtype;
	int count;
	POINT *points;
	char *text;
	float size;

    POINT GetPoint(int i);
} DrawingInfo;

class FlowGrapher
{
public:
	void SetNodeShape(char *fontcolor = NULL, char *fillcolor = NULL, char *fontname="Verdana", char *fontsize = "18");
	void AddNode(DWORD node_id,char *node_name,char *node_data);
	void AddLink(DWORD src, DWORD dst);
	int RenderToFile(char *format,char *filename);
	void GenerateDrawingInfo();
	int GetDrawingInfoLength();
	DrawingInfo *GetDrawingInfoMember(int i);
};
