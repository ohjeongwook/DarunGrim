#pragma once
#include <windows.h>

enum {
	TYPE_DI_RECTS=0,
	TYPE_DI_DRAW,
	TYPE_DI_GRAPH,
	TYPE_DI_COLOR,
	TYPE_DI_FILLCOLOR,
	TYPE_DI_BGCOLOR,
	TYPE_DI_FONTCOLOR
};

typedef struct _DrawingInfo_{
	DWORD address;
	BYTE type;
	BYTE subtype;
	int count;
	POINT *points;
	char *text;
	float size;

	POINT GetPoint(int i)
	{
		return points[i];
	}
} DrawingInfo;

