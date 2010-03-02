/* $Id: gvplugin_layout.h,v 1.8 2009/06/03 01:10:53 ellson Exp $ $Revision: 1.8 $ */
/* vim:set shiftwidth=4 ts=8: */

/**********************************************************
*      This software is part of the graphviz package      *
*                http://www.graphviz.org/                 *
*                                                         *
*            Copyright (c) 1994-2004 AT&T Corp.           *
*                and is licensed under the                *
*            Common Public License, Version 1.0           *
*                      by AT&T Corp.                      *
*                                                         *
*        Information and Software Systems Research        *
*              AT&T Research, Florham Park NJ             *
**********************************************************/

#ifndef GVPLUGIN_LAYOUT_H
#define GVPLUGIN_LAYOUT_H

#include "types.h"
#include "gvplugin.h"
#include "gvcjob.h"

#ifdef __cplusplus
extern "C" {
#endif

    struct gvlayout_engine_s {
	void (*layout) (graph_t * g);
	void (*cleanup) (graph_t * g);
    };

#ifdef __cplusplus
}
#endif
#endif				/* GVPLUGIN_LAYOUT_H */
