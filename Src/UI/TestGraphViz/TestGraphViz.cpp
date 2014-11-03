// TestGraphViz.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "FlowGrapher.h"

int _tmain(int argc, _TCHAR* argv[])
{
	FlowGrapher *pGraphVizProcessor = new FlowGrapher();
	pGraphVizProcessor->SetNodeShape("black", "red", "12");
	pGraphVizProcessor->AddNode(0, "Test", "Disasm lines");

	list<DrawingInfo *> *DrawingInfoMap;
	DrawingInfoMap = pGraphVizProcessor->GetDrawingInfo();
	return 0;
}

