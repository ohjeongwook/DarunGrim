// TestGraphViz.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "FlowGrapher.h"

int _tmain(int argc, _TCHAR* argv[])
{
	FlowGrapher *p_flow_grapher = new FlowGrapher();
	p_flow_grapher->SetNodeShape("black", "red", "12");
	p_flow_grapher->AddNode(0, "Test", "Disasm lines");

	p_flow_grapher->GenerateDrawingInfo();
	list<DrawingInfo *> *DrawingObjectList = p_flow_grapher->GetDrawingInfo();
	return 0;
}

