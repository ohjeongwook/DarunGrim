#include <windows.h>
#include "varray.h"

void varray_init(struct varray *p_pos,int element_size,int value)
{
	p_pos->element_size=element_size;
	p_pos->length=10;
	p_pos->ptr=(unsigned char *)malloc(p_pos->element_size*p_pos->length);
	if(p_pos->ptr)
		memset(p_pos->ptr,0,p_pos->element_size*p_pos->length);
}

void varray_deinit(struct varray *p_pos)
{
	if(p_pos && p_pos->ptr)
		free(p_pos->ptr);
}

PVOID varray_get(struct varray *p_pos,int i)
{
	if(p_pos->length<=i)
	{
		p_pos->ptr=(unsigned char *)realloc(p_pos->ptr,p_pos->element_size*(i+10));
		p_pos->length=i+10;
	}
	return (PVOID)(p_pos->ptr+p_pos->element_size*i);
}
