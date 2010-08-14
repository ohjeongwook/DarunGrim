#pragma once

//diff - compute a shortest edit script (SES) given two sequences

typedef enum {
	DIFF_MATCH = 1,
	DIFF_DELETE,
	DIFF_INSERT
} DiffOp;

typedef struct {
	short op;
	int off; /* off into s1 if MATCH or DELETE but s2 if INSERT */
	int len;
} DiffEdit;

int DiffArray(
	const void *a, int aoff, int n,
	const void *b, int boff, int m,
	void *context, int dmax,
	struct varray *ses, int *sn,
	struct varray *buf);

int GetStringSimilarity(const char *a,const char *b);
