#pragma once
#include<iostream>
#include "IDAAnalysisCommon.h"
using namespace std;

class DisassemblyProcessor
{
public:
    virtual void SetFileInfo(FileInfo fileInfo)
    {
        // FILE_INFO
        cout << "SetFileInfo" << endl;
    }

    virtual void EndAnalysis()
    {
        // END_OF_DATA
        cout << "EndAnalysis" << endl;
    }

    virtual void AddBasicBlock(PBasicBlock *p_basic_block)
    {
        // BASIC_BLOCK
        cout << "AddBasicBlock" << endl;
    }

    virtual void AddMapInfo(PMapInfo p_map_info)
    {
        // MAP_INFO
        cout << "AddMapInfo" << endl;
    }
};
