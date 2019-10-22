#pragma once

bool IsValidFunctionStart(ea_t address);
int ConnectFunctionChunks(ea_t address);
void FixFunctionChunks();