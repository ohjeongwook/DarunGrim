#pragma once

bool StartProcess(LPTSTR szCmdline);
void *malloc_wrapper(size_t size);
void *realloc(void *memblock,size_t old_size,size_t size);

void Execute(bool Wait,const char *format,...);
char *WriteToTemporaryFile(const char *format,...);
