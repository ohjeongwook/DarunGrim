#pragma once

bool IsValidFunctionStart(ea_t address);
int ConnectBrokenFunctionChunk(ea_t address);
void FindInvalidFunctionStartAndConnectBrokenFunctionChunk();