#pragma once

#include <stdlib.h>
#include <crtdbg.h>

#ifdef _DEBUGX
#define DEBUG_NEW new(_NORMAL_BLOCK, __FILE__, __LINE__)
#define new DEBUG_NEW
#endif

#define LOG_DARUNGRIM			0x00000001
#define LOG_DIFF_MACHINE		0x00000002
#define LOG_IDA_CONTROLLER		0x00000004
#define LOG_SQL					0x00000008
#define LOG_BASIC_BLOCK	0x0000000F
#define LOG_MATCH_RATE			0x00000010