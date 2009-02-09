// igit-enumfiles.c
//

#include <windows.h>
#include "igit.h"


// uses the ls-files code
#include "builtin-ls-files.c"


struct DirStatus
{
	// cached last access, to speed up searches (since we get a sorted list from git code)
	struct DirStatus *pLastAccessedChild;

	LPCSTR lpszName;

	struct DirStatus *next;
	struct DirStatus *children;
	struct DirStatus *parent;

	int nStatus;
};

static struct DirStatus l_dirTree;


static BOOL l_bNoRecurse;
static int l_nMinStatusRelevantForDirs;
static BOOL l_bSkipNormalDirs;
static int l_nEmptyDirStatus;
static BOOL l_bNoRecurseDir;

static BOOL l_bFullPath;
static char l_sFullPathBuf[2048];
static LPSTR l_lpszFileName;

static BOOL l_bDirStatus;
static int l_nLastStatus;


static inline char GetStatusChar(int nStatus)
{
	switch (nStatus)
	{
	case WGFS_Normal: return 'N';
	case WGFS_Modified: return 'M';
	//case WGFS_Staged: return 'S';
	//case WGFS_Added: return 'A';
	case WGFS_Conflicted: return 'C';
	case WGFS_Deleted: return 'D';

	case WGFS_Unknown: return '?';
	case WGFS_Empty: return 'E';
	//case WGFS_Unversioned: return 'U';
	}

	return '?';
}



static BOOL enum_ce_entry(struct cache_entry *ce, struct stat *st)
{
	// is this of any use (ce->ce_flags & CE_VALID) ?

	LPCSTR sFileName;

	if (!l_bFullPath)
	{
		sFileName = ce->name + prefix_offset;
	}
	else
	{
		strcpy(l_lpszFileName, ce->name);
		sFileName = l_sFullPathBuf;
	}

	const int nStage = ce_stage(ce);

	int nStatus = WGFS_Unknown;
	if (!st)
		nStatus = WGFS_Deleted;
	else if (nStage)
		nStatus = WGFS_Conflicted;
	else if ( ce_modified(ce, st, 0) )
		nStatus = WGFS_Modified;
	else
		nStatus = WGFS_Normal;
	l_nLastStatus = nStatus;

	// output format: "F status sha1 filename"

	fputs("F ", stdout);
	fputc(GetStatusChar(nStatus), stdout);
	fputc(' ', stdout);
	fputsha1(ce->sha1, stdout);
	fputc(' ', stdout);
	fputs(sFileName, stdout);
	fputc(0, stdout);

	return FALSE;
}

// same as enum except it skips enumeration and just determines status (used for recursive folder status)
// returns TRUE if file was processed
static BOOL process_ce_entry_status(struct cache_entry *ce, struct stat *st)
{
	// is this of any use (ce->ce_flags & CE_VALID) ?

	/*if (!l_bFullPath)
	{
		ef.sFileName = ce->name + offset;
	}
	else
	{
		strcpy(l_lpszFileName, ce->name);
		ef.sFileName = l_sFullPathBuf;
	}*/

	const int nStage = ce_stage(ce);

	UINT nStatus = WGFS_Unknown;
	if (!st)
		nStatus = WGFS_Deleted;
	else if (nStage)
		nStatus = WGFS_Conflicted;
	else if ( ce_modified(ce, st, 0) )
		nStatus = WGFS_Modified;
	else
		nStatus = WGFS_Normal;
	l_nLastStatus = nStatus;

	//ef.nStage = st ? ce_stage(ce) : 0;
	//ef.nFlags = 0;
	//ef.sha1 = ce->sha1;

	return TRUE;
}


static inline BOOL enum_dir(struct DirStatus *dir, LPCSTR lpszPathName)
{
	if (dir->nStatus == WGFS_Normal && l_bSkipNormalDirs)
		return FALSE;

	// output format: "D status pathname"

	fputs("D ", stdout);
	fputc(GetStatusChar(dir->nStatus), stdout);
	fputc(' ', stdout);
	fputs(lpszPathName, stdout);
	fputc(0, stdout);

	return FALSE;
}

static BOOL enum_dirs(struct DirStatus *dir, LPSTR sPathNameBuf)
{
	const int len = strlen(dir->lpszName);
	memcpy(sPathNameBuf, dir->lpszName, len);
	sPathNameBuf += len;
	*sPathNameBuf = 0;

	if ( enum_dir(dir, l_bFullPath ? l_sFullPathBuf : l_sFullPathBuf+prefix_offset) )
		return TRUE;

	if (!l_bNoRecurse && dir->children)
	{
		// recurse

		*sPathNameBuf++ = '/';
		*sPathNameBuf = 0;

		dir = dir->children;

		while (dir)
		{
			if ( enum_dirs(dir, sPathNameBuf) )
				return TRUE;

			dir = dir->next;
		}
	}

	return FALSE;
}


static struct DirStatus* GetSubDir(struct DirStatus *dir, LPCSTR lpszName, int nNameLenInclTerminator)
{
	// check for cached access
	if (dir->pLastAccessedChild
		&& !strcmp(dir->pLastAccessedChild->lpszName, lpszName))
	{
		return dir->pLastAccessedChild;
	}

	// search children
	struct DirStatus *p = dir->children;
	struct DirStatus *last = NULL;
	while (p)
	{
		if ( !strcmp(p->lpszName, lpszName) )
			return (dir->pLastAccessedChild = p);

		last = p;
		p = p->next;
	}

	// dir not accessed before, create new entry
	// TODO: do more efficient allocator (allocate larger pools, they can still be fire and forget and let our garbage collector clean up)
	p = dir->pLastAccessedChild = (struct DirStatus*) malloc(sizeof(struct DirStatus) + ((nNameLenInclTerminator+3)&~3));

	p->pLastAccessedChild = NULL;
	p->lpszName = (char*)p + sizeof(struct DirStatus);
	p->next = NULL;
	p->children = NULL;
	p->parent = dir;
	p->nStatus = l_nEmptyDirStatus;

	// append to list
	if (dir->children)
		last->next = p;
	else
		dir->children = p;

	// copy string
	memcpy((char*)p->lpszName, lpszName, nNameLenInclTerminator);

	return p;
}


static inline BOOL IsStatusRelevantForDirs(int nStatus)
{
	return nStatus >= l_nMinStatusRelevantForDirs && nStatus != WGFS_Deleted;
}


static void update_dirs_rec(LPCSTR lpszFileName, UINT nDirLen, struct cache_entry *ce, BOOL bStatusCached, struct DirStatus *parentDir)
{
	const int nDirLen1 = nDirLen+1;
	char s[nDirLen1];
	memcpy(s, lpszFileName, nDirLen);
	s[nDirLen] = 0;

	struct DirStatus *dir = GetSubDir(parentDir, s, nDirLen1);
	//ASSERT(dir != NULL);

	// TODO: if 'conflicted' status is added then need to check for that as highest prio
	if (dir->nStatus >= WGFS_Modified && l_bNoRecurse)
	{
		// no further processing needed
		return;
	}

	// process next subdir in lpszFileName

	lpszFileName += nDirLen1;

	LPCSTR p = strchr(lpszFileName, '/');
	if (!p)
	{
		// no more dirs in pathname (ie we are in the dir the file is located)

		if (!bStatusCached)
		{
			// file status not determined yet, do it now
			struct stat st;
			int err = lstat(ce->name, &st);
			if (!process_ce_entry_status(ce, err ? NULL : &st) || !IsStatusRelevantForDirs(l_nLastStatus))
				return;
		}
		const int nFileStatus = l_nLastStatus;

		if (nFileStatus > dir->nStatus)
		{
			// update status on dir and all parents
			do
			{
				if (nFileStatus > dir->nStatus)
					dir->nStatus = nFileStatus;
			}
			while ( (dir = dir->parent) );
		}
	}
	else if (lpszFileName != p) // quick check to make sure we're not left with a "/" filename
	{
		update_dirs_rec(lpszFileName, (UINT)(p-lpszFileName), ce, bStatusCached, dir);
	}
}

static void update_dirs(struct cache_entry *ce, int nPathNameOffset, BOOL bStatusCached)
{
	// filename relative to enumerated path
	LPCSTR lpszFileName = ce->name + nPathNameOffset;

	LPCSTR p = strchr(lpszFileName, '/');
	if (p <= lpszFileName)
	{
		// file is not in sub-dir

		if (!bStatusCached)
		{
			// file status not determined yet, do it now
			struct stat st;
			int err = lstat(ce->name, &st);
			if (!process_ce_entry_status(ce, err ? NULL : &st) || !IsStatusRelevantForDirs(l_nLastStatus))
				return;
		}
		const int nFileStatus = l_nLastStatus;

		if (nFileStatus > l_dirTree.nStatus)
			l_dirTree.nStatus = nFileStatus;

		return;
	}

	if (!l_bNoRecurseDir)
	{
		update_dirs_rec(lpszFileName, (UINT)(p-lpszFileName), ce, bStatusCached, &l_dirTree);
	}
}


static inline BOOL is_subpath(const char *sPath, int nPathLen, const char *sFile)
{
	return strchr(sFile + nPathLen, '/') != NULL;
}

static BOOL is_dir(const char *sProjectPath, const char *sSubPath)
{
	char s[2048];

	strcpy(s, sProjectPath);
	// backslashify
	LPSTR q = s;
	while (*q)
	{
		if (*q == '/')
			*q = '\\';
		q++;
	}
	// make sure it ends with a slash
	if (q[-1] != '\\')
		*q++ = '\\';
	strcpy(q, sSubPath);
	// backslashify sub-path
	while (*q)
	{
		if (*q == '/')
			*q = '\\';
		q++;
	}

	struct stat st;
	int err = lstat(s, &st);

	return (!err && S_ISDIR(st.st_mode));
}

static inline BOOL is_ce_name_eq(struct cache_entry *ce1, struct cache_entry *ce2)
{
	const size_t len1 = ce1->ce_flags & CE_NAMEMASK;
	const size_t len2 = ce2->ce_flags & CE_NAMEMASK;

	return (len1 == len2) ? !strcmp(ce1->name, ce2->name) : FALSE;
}


BOOL ig_enum_files(const char *pszProjectPath, const char *pszSubPath, const char *prefix, unsigned int nFlags)
{
	// reset all local vars of builtin-ls-files.c to default
	abbrev = 0;
	show_deleted = 0;
	show_cached = 0;
	show_others = 0;
	show_stage = 0;
	show_unmerged = 0;
	show_modified = 0;
	show_killed = 0;
	show_valid_bit = 0;
	line_terminator = '\n';
	prefix_len = 0;
	prefix_offset = 0;
	pathspec = 0;
	error_unmatch = 0;
	ps_matched = 0;
	with_tree = 0;
	tag_cached = "";
	tag_unmerged = "";
	tag_removed = "";
	tag_other = "";
	tag_killed = "";
	tag_modified = "";

	int i;
	//int exc_given = 0, require_work_tree = 0;
	struct dir_struct _dir;

	memset(&_dir, 0, sizeof(_dir));

	memset(&l_dirTree, 0, sizeof(l_dirTree));
	l_dirTree.nStatus = WGFS_Normal; // root dir is always at least WGFS_Normal even if empty
	if (pszSubPath && !(nFlags & WGEFF_EmptyAsNormal))
		l_dirTree.nStatus = WGFS_Empty;

	// NOTE: to force names to be relative to project root dir (no mater what current dir is) set prefix_offset to 0
	if (prefix)
		prefix_offset = strlen(prefix);
	git_config(git_default_config, NULL);

	struct dir_struct *dir = &_dir;

	const char *argv[2];
	argv[0] = pszSubPath;
	argv[1] = NULL;

	pathspec = get_pathspec(prefix, argv);

	// Verify that the pathspec matches the prefix
	if (pathspec)
		prefix = verify_pathspec(prefix);

	// Treat unmatching pathspec elements as errors
	if (pathspec && error_unmatch)
	{
		int num;
		for (num = 0; pathspec[num]; num++)
			;
		ps_matched = xcalloc(1, num);
	}

	// vars used for path recursion check
	int pathspec_len = 0;
	if (pathspec && *pathspec)
	{
		// calc length of pathspec plus 1 for a / (unless it already ends with a slash)
		pathspec_len = strlen(*pathspec);
		if ((*pathspec)[pathspec_len-1] != '/' && (*pathspec)[pathspec_len-1] != '\\')
			pathspec_len++;
	}
	const char *refpath = (pathspec && *pathspec) ? *pathspec : "";

	//
	// configure
	//

	l_bNoRecurseDir = FALSE;

	BOOL single_dir = (nFlags & WGEFF_SingleFile) && (!pszSubPath || is_dir(pszProjectPath, pszSubPath));
	// adjust other flags for best performance / correct results when WGEFF_SingleFile is set
	if (single_dir && (nFlags & WGEFF_NoRecurse))
		l_bNoRecurseDir = TRUE;
	if (nFlags & WGEFF_SingleFile)
	{
		nFlags |= WGEFF_NoRecurse;
		if (!single_dir)
			nFlags &= ~(WGEFF_DirStatusAll|WGEFF_DirStatusDelta);
	}
	if (single_dir)
	{
		nFlags = (nFlags & ~WGEFF_DirStatusAll) | WGEFF_DirStatusDelta;

		if ( !(nFlags & WGEFF_EmptyAsNormal) )
			l_dirTree.nStatus = WGFS_Empty;
	}

	BOOL no_recurse = nFlags & WGEFF_NoRecurse;
	l_bNoRecurse = no_recurse;
	l_bFullPath = nFlags & WGEFF_FullPath;
	l_bDirStatus = nFlags & (WGEFF_DirStatusDelta|WGEFF_DirStatusAll);

	// when all dirs should be enumerated we need IsStatusRelevantForDirs to report files of normal status as relevant
	// otherwise only above normal are considered, which is slightly more efficient
	l_nMinStatusRelevantForDirs = (nFlags & WGEFF_DirStatusAll) ? WGFS_Normal : (WGFS_Normal+1);

	// initial status of dirs
	l_nEmptyDirStatus = (nFlags & WGEFF_EmptyAsNormal) ? WGFS_Normal : WGFS_Empty;

	l_bSkipNormalDirs = ((nFlags & (WGEFF_DirStatusDelta|WGEFF_DirStatusAll)) == WGEFF_DirStatusDelta);

	*l_sFullPathBuf = 0;
	l_lpszFileName = NULL;
	if (l_bFullPath)
	{
		strcpy(l_sFullPathBuf, pszProjectPath);
		// slashify
		LPSTR q = l_sFullPathBuf;
		while (*q)
		{
			if (*q == '\\')
				*q = '/';
			q++;
		}
		// make sure it ends with a slash
		if (q[-1] != '/')
		{
			*q++ = '/';
			*q = 0;
		}
		// save pointer to where file paths, with project-relative names, can be concatenated
		l_lpszFileName = q;
	}

	// shouldn't have any effect but set them to reflect what we want listed
	show_cached = 1;
	show_modified = 1;
	show_deleted = 1;
	show_unmerged = 1;

	read_cache();
	if (prefix)
		prune_cache(prefix);

//if (pathspec && *pathspec) OutputDebugString(*pathspec);OutputDebugString(" (1)\r\n");
//if (prefix) OutputDebugString(prefix);OutputDebugString(" (2)\r\n");

	//
	// enum files
	//

	for (i=0; i<active_nr; i++)
	{
		struct cache_entry *ce = active_cache[i];
		struct stat st;
		int err;

		int dtype = ce_to_dtype(ce);

		if (excluded(dir, ce->name, &dtype) != dir->show_ignored)
			continue;
		if (ce->ce_flags & CE_UPDATE)
			continue;

		// skip file if not inside specified sub-path
		// this test was originally done in enum_ce_entry but in order to avoid unecessery lstat calls it was moved
		if (prefix_len >= ce_namelen(ce))
			die("git ls-files: internal error - cache entry not superset of prefix");
		if (pathspec && !pathspec_match(pathspec, ps_matched, ce->name, prefix_len))
			continue;

		if (single_dir || (no_recurse && is_subpath(refpath, pathspec_len, ce->name)))
		{
			if (l_bDirStatus)
				// this file would normally be skipped, but in order to determine correct dir status we need to process it
				update_dirs(ce, pathspec_len, FALSE);

			continue;
		}

		err = lstat(ce->name, &st);

		if ( enum_ce_entry(ce, err ? NULL : &st) )
			return TRUE;

		// normally (always?) conflicted/unmerged files will have 3 entries in a row (one in stage 1, one in 2 and one in 3)
		// skip redundant entries here
		if ( ce_stage(ce) )
		{
			int j;

			for (j=i+1; j<active_nr; j++)
			{
				struct cache_entry *nextce = active_cache[j];

				if ( !is_ce_name_eq(ce, nextce) )
					break;

				i = j;
			}
		}

		if (l_bDirStatus && IsStatusRelevantForDirs(l_nLastStatus))
			update_dirs(ce, pathspec_len, TRUE);
	}

	if (l_bDirStatus)
	{
		// enumerate dirs

		LPCSTR lpszRootDir="/";
		if (l_bFullPath)
		{
			lpszRootDir = l_sFullPathBuf;
			if (pathspec_len)
			{
				strcpy(l_lpszFileName, *pathspec);
				l_lpszFileName += pathspec_len;
			}

			*l_lpszFileName = 0;
			// remove trailng slash
			l_lpszFileName[-1] = 0;
		}
		else if (pathspec_len)
		{
			lpszRootDir = *pathspec;

			strcpy(l_sFullPathBuf, *pathspec);
			l_sFullPathBuf[pathspec_len-1] = '/';
			l_sFullPathBuf[pathspec_len] = 0;
			l_lpszFileName = l_sFullPathBuf;
		}
		else
		{
			lpszRootDir = ".";

			l_lpszFileName = l_sFullPathBuf;
		}

		if (single_dir)
		{
			// enumerate single dir
			l_bSkipNormalDirs = FALSE;
			enum_dir(&l_dirTree, lpszRootDir);
		}
		else if (!enum_dir(&l_dirTree, lpszRootDir) && l_dirTree.children)
		{
			if (l_bFullPath)
				// re-add trailing slash
				l_lpszFileName[-1] = '/';

			struct DirStatus *p = l_dirTree.children;

			do
			{
				if ( enum_dirs(p, l_lpszFileName) )
					break;
			}
			while ( (p = p->next) );
		}
	}

	return TRUE;
}


#if 0

/*
 * This merges the file listing in the directory cache index
 * with the actual working directory list, and shows different
 * combinations of the two.
 *
 * Copyright (C) Linus Torvalds, 2005
 */
#include "cache.h"
#include "quote.h"
#include "dir.h"
#include "builtin.h"
#include "tree.h"

static int abbrev;
static int show_deleted;
static int show_cached;
static int show_others;
static int show_stage;
static int show_unmerged;
static int show_modified;
static int show_killed;
static int show_valid_bit;
static int line_terminator = '\n';

static int prefix_len;
static int prefix_offset;
static const char **pathspec;
static int error_unmatch;
static char *ps_matched;
static const char *with_tree;

static const char *tag_cached = "";
static const char *tag_unmerged = "";
static const char *tag_removed = "";
static const char *tag_other = "";
static const char *tag_killed = "";
static const char *tag_modified = "";


/*
 * Match a pathspec against a filename. The first "skiplen" characters
 * are the common prefix
 */
int pathspec_match(const char **spec, char *ps_matched,
		   const char *filename, int skiplen)
{
	const char *m;

	while ((m = *spec++) != NULL) {
		int matchlen = strlen(m + skiplen);

		if (!matchlen)
			goto matched;
		if (!strncmp(m + skiplen, filename + skiplen, matchlen)) {
			if (m[skiplen + matchlen - 1] == '/')
				goto matched;
			switch (filename[skiplen + matchlen]) {
			case '/': case '\0':
				goto matched;
			}
		}
		if (!fnmatch(m + skiplen, filename + skiplen, 0))
			goto matched;
		if (ps_matched)
			ps_matched++;
		continue;
	matched:
		if (ps_matched)
			*ps_matched = 1;
		return 1;
	}
	return 0;
}

static void show_dir_entry(const char *tag, struct dir_entry *ent)
{
	int len = prefix_len;
	int offset = prefix_offset;

	if (len >= ent->len)
		die("git ls-files: internal error - directory entry not superset of prefix");

	if (pathspec && !pathspec_match(pathspec, ps_matched, ent->name, len))
		return;

	fputs(tag, stdout);
	write_name_quoted(ent->name + offset, stdout, line_terminator);
}

static void show_other_files(struct dir_struct *dir)
{
	int i;

	for (i = 0; i < dir->nr; i++) {
		struct dir_entry *ent = dir->entries[i];
		if (!cache_name_is_other(ent->name, ent->len))
			continue;
		show_dir_entry(tag_other, ent);
	}
}

static void show_killed_files(struct dir_struct *dir)
{
	int i;
	for (i = 0; i < dir->nr; i++) {
		struct dir_entry *ent = dir->entries[i];
		char *cp, *sp;
		int pos, len, killed = 0;

		for (cp = ent->name; cp - ent->name < ent->len; cp = sp + 1) {
			sp = strchr(cp, '/');
			if (!sp) {
				/* If ent->name is prefix of an entry in the
				 * cache, it will be killed.
				 */
				pos = cache_name_pos(ent->name, ent->len);
				if (0 <= pos)
					die("bug in show-killed-files");
				pos = -pos - 1;
				while (pos < active_nr &&
				       ce_stage(active_cache[pos]))
					pos++; /* skip unmerged */
				if (active_nr <= pos)
					break;
				/* pos points at a name immediately after
				 * ent->name in the cache.  Does it expect
				 * ent->name to be a directory?
				 */
				len = ce_namelen(active_cache[pos]);
				if ((ent->len < len) &&
				    !strncmp(active_cache[pos]->name,
					     ent->name, ent->len) &&
				    active_cache[pos]->name[ent->len] == '/')
					killed = 1;
				break;
			}
			if (0 <= cache_name_pos(ent->name, sp - ent->name)) {
				/* If any of the leading directories in
				 * ent->name is registered in the cache,
				 * ent->name will be killed.
				 */
				killed = 1;
				break;
			}
		}
		if (killed)
			show_dir_entry(tag_killed, dir->entries[i]);
	}
}

static void show_ce_entry(const char *tag, struct cache_entry *ce)
{
	int len = prefix_len;
	int offset = prefix_offset;

	if (len >= ce_namelen(ce))
		die("git ls-files: internal error - cache entry not superset of prefix");

	if (pathspec && !pathspec_match(pathspec, ps_matched, ce->name, len))
		return;

	if (tag && *tag && show_valid_bit &&
	    (ce->ce_flags & CE_VALID)) {
		static char alttag[4];
		memcpy(alttag, tag, 3);
		if (isalpha(tag[0]))
			alttag[0] = tolower(tag[0]);
		else if (tag[0] == '?')
			alttag[0] = '!';
		else {
			alttag[0] = 'v';
			alttag[1] = tag[0];
			alttag[2] = ' ';
			alttag[3] = 0;
		}
		tag = alttag;
	}

	if (!show_stage) {
		fputs(tag, stdout);
	} else {
		printf("%s%06o %s %d\t",
		       tag,
		       ce->ce_mode,
		       abbrev ? find_unique_abbrev(ce->sha1,abbrev)
				: sha1_to_hex(ce->sha1),
		       ce_stage(ce));
	}
	write_name_quoted(ce->name + offset, stdout, line_terminator);
}

static void show_files(struct dir_struct *dir, const char *prefix)
{
	int i;

	/* For cached/deleted files we don't need to even do the readdir */
	if (show_others || show_killed) {
		const char *path = ".", *base = "";
		int baselen = prefix_len;

		if (baselen)
			path = base = prefix;
		read_directory(dir, path, base, baselen, pathspec);
		if (show_others)
			show_other_files(dir);
		if (show_killed)
			show_killed_files(dir);
	}
	if (show_cached | show_stage) {
		for (i = 0; i < active_nr; i++) {
			struct cache_entry *ce = active_cache[i];
			int dtype = ce_to_dtype(ce);
			if (excluded(dir, ce->name, &dtype) != dir->show_ignored)
				continue;
			if (show_unmerged && !ce_stage(ce))
				continue;
			if (ce->ce_flags & CE_UPDATE)
				continue;
			show_ce_entry(ce_stage(ce) ? tag_unmerged : tag_cached, ce);
		}
	}
	if (show_deleted | show_modified) {
		for (i = 0; i < active_nr; i++) {
			struct cache_entry *ce = active_cache[i];
			struct stat st;
			int err;
			int dtype = ce_to_dtype(ce);
			if (excluded(dir, ce->name, &dtype) != dir->show_ignored)
				continue;
			if (ce->ce_flags & CE_UPDATE)
				continue;
			err = lstat(ce->name, &st);
			if (show_deleted && err)
				show_ce_entry(tag_removed, ce);
			if (show_modified && ce_modified(ce, &st, 0))
				show_ce_entry(tag_modified, ce);
		}
	}
}

/*
 * Prune the index to only contain stuff starting with "prefix"
 */
static void prune_cache(const char *prefix)
{
	int pos = cache_name_pos(prefix, prefix_len);
	unsigned int first, last;

	if (pos < 0)
		pos = -pos-1;
	memmove(active_cache, active_cache + pos,
		(active_nr - pos) * sizeof(struct cache_entry *));
	active_nr -= pos;
	first = 0;
	last = active_nr;
	while (last > first) {
		int next = (last + first) >> 1;
		struct cache_entry *ce = active_cache[next];
		if (!strncmp(ce->name, prefix, prefix_len)) {
			first = next+1;
			continue;
		}
		last = next;
	}
	active_nr = last;
}

static const char *verify_pathspec(const char *prefix)
{
	const char **p, *n, *prev;
	unsigned long max;

	prev = NULL;
	max = PATH_MAX;
	for (p = pathspec; (n = *p) != NULL; p++) {
		int i, len = 0;
		for (i = 0; i < max; i++) {
			char c = n[i];
			if (prev && prev[i] != c)
				break;
			if (!c || c == '*' || c == '?')
				break;
			if (c == '/')
				len = i+1;
		}
		prev = n;
		if (len < max) {
			max = len;
			if (!max)
				break;
		}
	}

	if (prefix_offset > max || memcmp(prev, prefix, prefix_offset))
		die("git ls-files: cannot generate relative filenames containing '..'");

	prefix_len = max;
	return max ? xmemdupz(prev, max) : NULL;
}

/*
 * Read the tree specified with --with-tree option
 * (typically, HEAD) into stage #1 and then
 * squash them down to stage #0.  This is used for
 * --error-unmatch to list and check the path patterns
 * that were given from the command line.  We are not
 * going to write this index out.
 */
void overlay_tree_on_cache(const char *tree_name, const char *prefix)
{
	struct tree *tree;
	unsigned char sha1[20];
	const char **match;
	struct cache_entry *last_stage0 = NULL;
	int i;

	if (get_sha1(tree_name, sha1))
		die("tree-ish %s not found.", tree_name);
	tree = parse_tree_indirect(sha1);
	if (!tree)
		die("bad tree-ish %s", tree_name);

	/* Hoist the unmerged entries up to stage #3 to make room */
	for (i = 0; i < active_nr; i++) {
		struct cache_entry *ce = active_cache[i];
		if (!ce_stage(ce))
			continue;
		ce->ce_flags |= CE_STAGEMASK;
	}

	if (prefix) {
		static const char *(matchbuf[2]);
		matchbuf[0] = prefix;
		matchbuf[1] = NULL;
		match = matchbuf;
	} else
		match = NULL;
	if (read_tree(tree, 1, match))
		die("unable to read tree entries %s", tree_name);

	for (i = 0; i < active_nr; i++) {
		struct cache_entry *ce = active_cache[i];
		switch (ce_stage(ce)) {
		case 0:
			last_stage0 = ce;
			/* fallthru */
		default:
			continue;
		case 1:
			/*
			 * If there is stage #0 entry for this, we do not
			 * need to show it.  We use CE_UPDATE bit to mark
			 * such an entry.
			 */
			if (last_stage0 &&
			    !strcmp(last_stage0->name, ce->name))
				ce->ce_flags |= CE_UPDATE;
		}
	}
}

int report_path_error(const char *ps_matched, const char **pathspec, int prefix_offset)
{
	/*
	 * Make sure all pathspec matched; otherwise it is an error.
	 */
	int num, errors = 0;
	for (num = 0; pathspec[num]; num++) {
		int other, found_dup;

		if (ps_matched[num])
			continue;
		/*
		 * The caller might have fed identical pathspec
		 * twice.  Do not barf on such a mistake.
		 */
		for (found_dup = other = 0;
		     !found_dup && pathspec[other];
		     other++) {
			if (other == num || !ps_matched[other])
				continue;
			if (!strcmp(pathspec[other], pathspec[num]))
				/*
				 * Ok, we have a match already.
				 */
				found_dup = 1;
		}
		if (found_dup)
			continue;

		error("pathspec '%s' did not match any file(s) known to git.",
		      pathspec[num] + prefix_offset);
		errors++;
	}
	return errors;
}

static const char ls_files_usage[] =
	"git ls-files [-z] [-t] [-v] (--[cached|deleted|others|stage|unmerged|killed|modified])* "
	"[ --ignored ] [--exclude=<pattern>] [--exclude-from=<file>] "
	"[ --exclude-per-directory=<filename> ] [--exclude-standard] "
	"[--full-name] [--abbrev] [--] [<file>]*";

int cmd_ls_files(int argc, const char **argv, const char *prefix)
{
	int i;
	int exc_given = 0, require_work_tree = 0;
	struct dir_struct dir;

	memset(&dir, 0, sizeof(dir));
	if (prefix)
		prefix_offset = strlen(prefix);
	git_config(git_default_config, NULL);

	for (i = 1; i < argc; i++) {
		const char *arg = argv[i];

		if (!strcmp(arg, "--")) {
			i++;
			break;
		}
		if (!strcmp(arg, "-z")) {
			line_terminator = 0;
			continue;
		}
		if (!strcmp(arg, "-t") || !strcmp(arg, "-v")) {
			tag_cached = "H ";
			tag_unmerged = "M ";
			tag_removed = "R ";
			tag_modified = "C ";
			tag_other = "? ";
			tag_killed = "K ";
			if (arg[1] == 'v')
				show_valid_bit = 1;
			continue;
		}
		if (!strcmp(arg, "-c") || !strcmp(arg, "--cached")) {
			show_cached = 1;
			continue;
		}
		if (!strcmp(arg, "-d") || !strcmp(arg, "--deleted")) {
			show_deleted = 1;
			continue;
		}
		if (!strcmp(arg, "-m") || !strcmp(arg, "--modified")) {
			show_modified = 1;
			require_work_tree = 1;
			continue;
		}
		if (!strcmp(arg, "-o") || !strcmp(arg, "--others")) {
			show_others = 1;
			require_work_tree = 1;
			continue;
		}
		if (!strcmp(arg, "-i") || !strcmp(arg, "--ignored")) {
			dir.show_ignored = 1;
			require_work_tree = 1;
			continue;
		}
		if (!strcmp(arg, "-s") || !strcmp(arg, "--stage")) {
			show_stage = 1;
			continue;
		}
		if (!strcmp(arg, "-k") || !strcmp(arg, "--killed")) {
			show_killed = 1;
			require_work_tree = 1;
			continue;
		}
		if (!strcmp(arg, "--directory")) {
			dir.show_other_directories = 1;
			continue;
		}
		if (!strcmp(arg, "--no-empty-directory")) {
			dir.hide_empty_directories = 1;
			continue;
		}
		if (!strcmp(arg, "-u") || !strcmp(arg, "--unmerged")) {
			/* There's no point in showing unmerged unless
			 * you also show the stage information.
			 */
			show_stage = 1;
			show_unmerged = 1;
			continue;
		}
		if (!strcmp(arg, "-x") && i+1 < argc) {
			exc_given = 1;
			add_exclude(argv[++i], "", 0, &dir.exclude_list[EXC_CMDL]);
			continue;
		}
		if (!prefixcmp(arg, "--exclude=")) {
			exc_given = 1;
			add_exclude(arg+10, "", 0, &dir.exclude_list[EXC_CMDL]);
			continue;
		}
		if (!strcmp(arg, "-X") && i+1 < argc) {
			exc_given = 1;
			add_excludes_from_file(&dir, argv[++i]);
			continue;
		}
		if (!prefixcmp(arg, "--exclude-from=")) {
			exc_given = 1;
			add_excludes_from_file(&dir, arg+15);
			continue;
		}
		if (!prefixcmp(arg, "--exclude-per-directory=")) {
			exc_given = 1;
			dir.exclude_per_dir = arg + 24;
			continue;
		}
		if (!strcmp(arg, "--exclude-standard")) {
			exc_given = 1;
			setup_standard_excludes(&dir);
			continue;
		}
		if (!strcmp(arg, "--full-name")) {
			prefix_offset = 0;
			continue;
		}
		if (!strcmp(arg, "--error-unmatch")) {
			error_unmatch = 1;
			continue;
		}
		if (!prefixcmp(arg, "--with-tree=")) {
			with_tree = arg + 12;
			continue;
		}
		if (!prefixcmp(arg, "--abbrev=")) {
			abbrev = strtoul(arg+9, NULL, 10);
			if (abbrev && abbrev < MINIMUM_ABBREV)
				abbrev = MINIMUM_ABBREV;
			else if (abbrev > 40)
				abbrev = 40;
			continue;
		}
		if (!strcmp(arg, "--abbrev")) {
			abbrev = DEFAULT_ABBREV;
			continue;
		}
		if (*arg == '-')
			usage(ls_files_usage);
		break;
	}

	if (require_work_tree && !is_inside_work_tree())
		setup_work_tree();

	pathspec = get_pathspec(prefix, argv + i);

	/* Verify that the pathspec matches the prefix */
	if (pathspec)
		prefix = verify_pathspec(prefix);

	/* Treat unmatching pathspec elements as errors */
	if (pathspec && error_unmatch) {
		int num;
		for (num = 0; pathspec[num]; num++)
			;
		ps_matched = xcalloc(1, num);
	}

	if (dir.show_ignored && !exc_given) {
		fprintf(stderr, "%s: --ignored needs some exclude pattern\n",
			argv[0]);
		exit(1);
	}

	/* With no flags, we default to showing the cached files */
	if (!(show_stage | show_deleted | show_others | show_unmerged |
	      show_killed | show_modified))
		show_cached = 1;

	read_cache();
	if (prefix)
		prune_cache(prefix);
	if (with_tree) {
		/*
		 * Basic sanity check; show-stages and show-unmerged
		 * would not make any sense with this option.
		 */
		if (show_stage || show_unmerged)
			die("ls-files --with-tree is incompatible with -s or -u");
		overlay_tree_on_cache(with_tree, prefix);
	}
	show_files(&dir, prefix);

	if (ps_matched) {
		int bad;
		bad = report_path_error(ps_matched, pathspec, prefix_offset);
		if (bad)
			fprintf(stderr, "Did you forget to 'git add'?\n");

		return bad ? 1 : 0;
	}

	return 0;
}

#endif
