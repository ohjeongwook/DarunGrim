#pragma once
#include <windows.h>
#include <stdio.h>

char *GetRegValueString(const char *key_name, const char *value_name);
bool GetRegValueInteger(const char *key_name, const char *value_name, DWORD& value);
