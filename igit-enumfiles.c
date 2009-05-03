// igit-enumfiles.c
//

#include <windows.h>
#include "igit.h"

#include "cache.h"
#include "commit.h"
#include "diff.h"
#include "diffcore.h"
#include "revision.h"
#include "cache-tree.h"
#include "unpack-trees.h"
#include "reflog-walk.h"


// uses the ls-files code
#include "builtin-ls-files.c"


// custom cache entry flags (just to make sure that no git functions get confused)
#define CE_IG_ADDED		0x2000000
#define CE_IG_DELETED	0x4000000
#define CE_IG_STAGED	0x8000000


struct DirStatus
{
	// cached last access, to speed up searches (since we get a sorted list from git code)
	struct DirStatus *pLastAccessedChild;

	LPCSTR lpszName;

	struct DirStatus *next;
	struct DirStatus *children;
	struct DirStatus *parent;

	int nStatus;
	BOOL bExplicitlyIgnored;
};

static struct DirStatus l_dirTree;


struct EntryRef
{
	struct cache_entry *ce;
	struct EntryRef *next;
};

static struct EntryRef *l_delQueue = NULL;


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
static int l_nEnumeratedCached = 0;

static BOOL l_bHasHistory = FALSE;


static inline char GetStatusChar(int nStatus)
{
	switch (nStatus)
	{
	case WGFS_Normal: return 'N';
	case WGFS_Modified: return 'M';
	case WGFS_Staged: return 'S';
	case WGFS_Added: return 'A';
	case WGFS_Conflicted: return 'C';
	case WGFS_Deleted: return 'D';

	case WGFS_Unversioned: return 'U';
	case WGFS_Ignored: return 'I';
	case WGFS_Unknown: return '?';
	case WGFS_Empty: return 'E';
	}

	return '?';
}


static inline void queue_deleted(struct cache_entry *ce)
{
	struct EntryRef *p = (struct EntryRef*) malloc( sizeof(struct EntryRef) );

	p->ce = ce;

	p->next = l_delQueue;
	l_delQueue = p;
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
	if (!st || (ce->ce_flags & CE_IG_DELETED))
		nStatus = WGFS_Deleted;
	else if (nStage)
		nStatus = WGFS_Conflicted;
	else if (ce->ce_flags & CE_IG_ADDED)
		nStatus = WGFS_Added;
	else if ( ce_modified(ce, st, 0) )
		nStatus = WGFS_Modified;
	else if (ce->ce_flags & CE_IG_STAGED)
		nStatus = WGFS_Staged;
	else if (!l_bHasHistory)
		nStatus = WGFS_Added;
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

	l_nEnumeratedCached++;

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
	if (!st || (ce->ce_flags & CE_IG_DELETED))
		nStatus = WGFS_Deleted;
	else if (nStage)
		nStatus = WGFS_Conflicted;
	else if (ce->ce_flags & CE_IG_ADDED)
		nStatus = WGFS_Added;
	else if ( ce_modified(ce, st, 0) )
		nStatus = WGFS_Modified;
	else if (ce->ce_flags & CE_IG_STAGED)
		nStatus = WGFS_Staged;
	else if (!l_bHasHistory)
		nStatus = WGFS_Added;
	else
		nStatus = WGFS_Normal;
	l_nLastStatus = nStatus;

	//ef.nStage = st ? ce_stage(ce) : 0;
	//ef.nFlags = 0;
	//ef.sha1 = ce->sha1;

	return TRUE;
}


static void update_dirs_unversioned(struct dir_entry *ce, int nPathNameOffset);

static void enum_unversioned(struct dir_entry **files, int nr, BOOL bIgnored)
{
	int i;
	for (i=0; i<nr; i++)
	{
		struct dir_entry *ent = files[i];

		if (ent->name[ent->len-1] != '/' && !cache_name_is_other(ent->name, ent->len))
			continue;

		int len = prefix_len;

		if (len >= ent->len)
			die("igit status: internal error - directory entry not superset of prefix");

		if (pathspec && !match_pathspec(pathspec, ent->name, ent->len, len, ps_matched))
			continue;

		LPCSTR sFileName;

		if (!l_bFullPath)
		{
			sFileName = ent->name + prefix_offset;
		}
		else
		{
			strcpy(l_lpszFileName, ent->name);
			sFileName = l_sFullPathBuf;
		}

		if (bIgnored)
		{
			// because we specified collect_all_ignored this may be a directory that was ignored
			if (ent->name[ent->len-1] != '/')
			{
				if (l_bDirStatus)
				{
					l_nLastStatus = WGFS_Ignored;
					update_dirs_unversioned(ent, len);
				}

				fputs("F I 0000000000000000000000000000000000000000 ", stdout);
			}
			else
			{
				if (l_bDirStatus)
				{
					const int nOrgEmptyDirStatus = l_nEmptyDirStatus;
					l_nLastStatus = l_nEmptyDirStatus = WGFS_Ignored;
					update_dirs_unversioned(ent, len);
					l_nEmptyDirStatus = nOrgEmptyDirStatus;
				}

				continue;
			}
		}
		else
		{
			if (ent->name[ent->len-1] != '/')
			{
				if (l_bDirStatus)
				{
					l_nLastStatus = WGFS_Unversioned;
					update_dirs_unversioned(ent, len);
				}

				fputs("F U 0000000000000000000000000000000000000000 ", stdout);
			}
			else
			{
				if (l_bDirStatus)
				{
					l_nLastStatus = l_nEmptyDirStatus;
					update_dirs_unversioned(ent, len);
				}

				continue;
			}
		}
		fputs(sFileName, stdout);
		fputc(0, stdout);
	}
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
	if (l_nEmptyDirStatus != WGFS_Ignored)
	{
		p->bExplicitlyIgnored = dir->bExplicitlyIgnored;
		p->nStatus = (p->bExplicitlyIgnored && l_nEmptyDirStatus < WGFS_Ignored) ? WGFS_Ignored : l_nEmptyDirStatus;
	}
	else
	{
		p->nStatus = WGFS_Ignored;
		p->bExplicitlyIgnored = TRUE;
	}

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


static void update_dirs_unversioned_rec(LPCSTR lpszFileName, UINT nDirLen, struct dir_entry *ce, struct DirStatus *parentDir)
{
	const int nDirLen1 = nDirLen+1;
	char s[nDirLen1];
	memcpy(s, lpszFileName, nDirLen);
	s[nDirLen] = 0;

	struct DirStatus *dir = GetSubDir(parentDir, s, nDirLen1);
	//ASSERT(dir != NULL);

	if (dir->nStatus >= WGFS_Conflicted && l_bNoRecurse)
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

		if (l_nEmptyDirStatus == WGFS_Unknown)
			// only want dirs enumerated without recursive status
			return;

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
		update_dirs_unversioned_rec(lpszFileName, (UINT)(p-lpszFileName), ce, dir);
	}
}

static void update_dirs_unversioned(struct dir_entry *ce, int nPathNameOffset)
{
	// filename relative to enumerated path
	LPCSTR lpszFileName = ce->name + nPathNameOffset;

	LPCSTR p = strchr(lpszFileName, '/');
	if (p <= lpszFileName)
	{
		// file is not in sub-dir

		if (l_nEmptyDirStatus == WGFS_Unknown)
			// only want dirst enumerated without recursive status
			return;

		const int nFileStatus = l_nLastStatus;

		if (nFileStatus > l_dirTree.nStatus)
			l_dirTree.nStatus = nFileStatus;

		return;
	}

	if (!l_bNoRecurseDir)
	{
		update_dirs_unversioned_rec(lpszFileName, (UINT)(p-lpszFileName), ce, &l_dirTree);
	}
}


static void update_dirs_rec(LPCSTR lpszFileName, UINT nDirLen, struct cache_entry *ce, BOOL bStatusCached, struct DirStatus *parentDir)
{
	const int nDirLen1 = nDirLen+1;
	char s[nDirLen1];
	memcpy(s, lpszFileName, nDirLen);
	s[nDirLen] = 0;

	struct DirStatus *dir = GetSubDir(parentDir, s, nDirLen1);
	//ASSERT(dir != NULL);

	if (dir->nStatus >= WGFS_Conflicted && l_bNoRecurse)
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

		if (l_nEmptyDirStatus == WGFS_Unknown)
			// only want dirst enumerated without recursive status
			return;

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

		 if (l_nEmptyDirStatus == WGFS_Unknown)
			 // only want dirs enumerated without recursive status
			return;

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


struct oneway_unpack_data {
	struct rev_info *revs;
	char symcache[PATH_MAX];
};

// modified version of function in diff-lib.c
static void do_oneway_diff(struct unpack_trees_options *o, struct cache_entry *idx, struct cache_entry *tree)
{
	if (!tree)
	{
		if (idx)
		{
			// file has no previous commit, newly added
			idx->ce_flags |= CE_IG_ADDED;
		}
	}
	else if (!idx)
	{
		// file only in previous commit, deleted
		tree->ce_flags |= CE_IG_DELETED;
		queue_deleted(tree);
	}
	else if (!(idx->ce_flags & CE_INTENT_TO_ADD)
		&& hashcmp(tree->sha1, idx->sha1) && !is_null_sha1(idx->sha1))
	{
		// file modified and in both indices, staged
		idx->ce_flags |= CE_IG_STAGED;
	}
}

// function taken from diff-lib.c
static inline void skip_same_name(struct cache_entry *ce, struct unpack_trees_options *o)
{
	int len = ce_namelen(ce);
	const struct index_state *index = o->src_index;

	while (o->pos < index->cache_nr) {
		struct cache_entry *next = index->cache[o->pos];
		if (len != ce_namelen(next))
			break;
		if (memcmp(ce->name, next->name, len))
			break;
		o->pos++;
	}
}

// function taken from diff-lib.c
static int oneway_diff(struct cache_entry **src, struct unpack_trees_options *o)
{
	struct cache_entry *idx = src[0];
	struct cache_entry *tree = src[1];
	struct oneway_unpack_data *cbdata = o->unpack_data;
	struct rev_info *revs = cbdata->revs;

	if (idx && ce_stage(idx))
		skip_same_name(idx, o);

	/*
	 * Unpack-trees generates a DF/conflict entry if
	 * there was a directory in the index and a tree
	 * in the tree. From a diff standpoint, that's a
	 * delete of the tree and a create of the file.
	 */
	if (tree == o->df_conflict_entry)
		tree = NULL;

	if (ce_path_match(idx ? idx : tree, revs->prune_data))
		do_oneway_diff(o, idx, tree);

	return 0;
}

/*
 * This turns all merge entries into "stage 3". That guarantees that
 * when we read in the new tree (into "stage 1"), we won't lose sight
 * of the fact that we had unmerged entries.
 */
static void mark_merge_entries(void)
{
	int i;
	for (i = 0; i < active_nr; i++) {
		struct cache_entry *ce = active_cache[i];
		if (!ce_stage(ce))
			continue;
		ce->ce_flags |= CE_STAGEMASK;
	}
}

static void preprocess_index(struct rev_info *revs)
{
	// compare current index with index from last commit to detect staged and newly added files

	//
	// based on run_diff_index()
	//

	struct object *ent;
	struct tree *tree;
	const char *tree_name;
	struct unpack_trees_options opts;
	struct tree_desc t;
	struct oneway_unpack_data unpack_cb;

	mark_merge_entries();

	ent = revs->pending.objects[0].item;
	tree_name = revs->pending.objects[0].name;
	tree = parse_tree_indirect(ent->sha1);
	if (!tree)
		// bad tree object
		return;

	unpack_cb.revs = revs;
	unpack_cb.symcache[0] = '\0';
	memset(&opts, 0, sizeof(opts));
	opts.head_idx = 1;
	opts.index_only = 1;
	opts.merge = 1;
	opts.fn = oneway_diff;
	opts.unpack_data = &unpack_cb;
	opts.src_index = &the_index;
	opts.dst_index = NULL;

	init_tree_desc(&t, tree->buffer, tree->size);

	if ( unpack_trees(1, &t, &opts) )
		// failed to unpack
		return;

	// add deleted files to index (easier for enumeration functions to process)
	if (l_delQueue)
	{
		struct EntryRef *p = l_delQueue;

		while (p)
		{
			// only add file for enumeration if they still exist
			struct stat st;
			if ( lstat(p->ce->name, &st) )
			{
				struct cache_entry *ce = make_cache_entry(p->ce->ce_mode, null_sha1, p->ce->name, 0, 0);

				add_index_entry(&the_index, ce, ADD_CACHE_OK_TO_ADD|ADD_CACHE_SKIP_DFCHECK|ADD_CACHE_NEW_ONLY);
				ce->ce_flags &= ~CE_ADDED;
				ce->ce_flags |= CE_IG_DELETED;
			}

			struct EntryRef *q = p;
			p = p->next;

			free(q);
		}

		l_delQueue = NULL;
	}
}


static struct object *get_reference(struct rev_info *revs, const char *name, const unsigned char *sha1, unsigned int flags)
{
	struct object *object;

	object = parse_object(sha1);
	if (!object)
		return NULL;//die("bad object %s", name);
	object->flags |= flags;
	return object;
}

static int add_pending_object_with_mode(struct rev_info *revs, struct object *obj, const char *name, unsigned mode)
{
	if (revs->no_walk && (obj->flags & UNINTERESTING))
		return 1;//die("object ranges do not make sense when not walking revisions");
	if (revs->reflog_info && obj->type == OBJ_COMMIT
		&& add_reflog_for_walk(revs->reflog_info, (struct commit *)obj, name))
		return 0;
	add_object_array_with_mode(obj, name, &revs->pending, mode);
	return 0;
}

static int setup_revisions_lite(struct rev_info *revs, const char *def)
{
	if (revs->def == NULL)
		revs->def = def;
	if (revs->def && !revs->pending.nr) {
		unsigned char sha1[20];
		struct object *object;
		unsigned mode;
		if (get_sha1_with_mode(revs->def, sha1, &mode))
			return 1;//die("bad default revision '%s'", revs->def);
		object = get_reference(revs, revs->def, sha1, 0);
		if (!object)
			return 2;
		if ( add_pending_object_with_mode(revs, object, revs->def, mode) )
			return 3;
	}

	/* Did the user ask for any diff output? Run the diff! */
	if (revs->diffopt.output_format & ~DIFF_FORMAT_NO_OUTPUT)
		revs->diff = 1;

	/* Pickaxe, diff-filter and rename following need diffs */
	if (revs->diffopt.pickaxe ||
	    revs->diffopt.filter ||
	    DIFF_OPT_TST(&revs->diffopt, FOLLOW_RENAMES))
		revs->diff = 1;

	if (revs->topo_order)
		revs->limited = 1;

	if (revs->prune_data) {
		diff_tree_setup_paths(revs->prune_data, &revs->pruning);
		/* Can't prune commits with rename following: the paths change.. */
		if (!DIFF_OPT_TST(&revs->diffopt, FOLLOW_RENAMES))
			revs->prune = 1;
		if (!revs->full_diff)
			diff_tree_setup_paths(revs->prune_data, &revs->diffopt);
	}
	if (revs->combine_merges) {
		revs->ignore_merges = 0;
		if (revs->dense_combined_merges && !revs->diffopt.output_format)
			revs->diffopt.output_format = DIFF_FORMAT_PATCH;
	}
	revs->diffopt.abbrev = revs->abbrev;
	if (diff_setup_done(&revs->diffopt) < 0)
		return 4;//die("diff_setup_done failed");

	compile_grep_patterns(&revs->grep_filter);

	/*if (revs->reverse && revs->reflog_info)
		die("cannot combine --reverse with --walk-reflogs");
	if (revs->rewrite_parents && revs->children.name)
		die("cannot combine --parents and --children");*/

	/*
	 * Limitations on the graph functionality
	 */
	/*if (revs->reverse && revs->graph)
		die("cannot combine --reverse with --graph");

	if (revs->reflog_info && revs->graph)
		die("cannot combine --walk-reflogs with --graph");*/

	return 0;
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

	const BOOL bSubDir = pszSubPath && is_dir(pszProjectPath, pszSubPath);

	LPCSTR pszSubPathSpec = pszSubPath;
	if (bSubDir && !(nFlags & WGEFF_SingleFile))
	{
		int len = strlen(pszSubPath);
		char *s = (char*)malloc(len+3);
		strcpy(s, pszSubPath);
		strcpy(s+len, "/*");
		pszSubPathSpec = s;
	}

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
	argv[0] = pszSubPathSpec;
	argv[1] = NULL;

	if (/*require_work_tree &&*/ !is_inside_work_tree())
		setup_work_tree();

	pathspec = get_pathspec(prefix, argv);

	// TODO: in ls-files from v1.6.2 read_cache call was moved up here, not sure if that is needed or works correctly here
	//read_cache();

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
		if ((*pathspec)[pathspec_len-1] == '*')
			pathspec_len--;
		if ((*pathspec)[pathspec_len-1] != '/')
			pathspec_len++;
	}
	const char *refpath = (pathspec && *pathspec) ? *pathspec : "";

	//
	// configure
	//

	l_bNoRecurseDir = FALSE;

	BOOL single_dir = (nFlags & WGEFF_SingleFile) && (!pszSubPath || bSubDir);
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

	// when all dirs should be enumerated we need IsStatusRelevantForDirs to report files of any status as relevant
	// otherwise only above normal are considered, which is slightly more efficient
	l_nMinStatusRelevantForDirs = (nFlags & WGEFF_DirStatusAll) ? WGFS_Empty : (WGFS_Normal+1);

	// initial status of dirs
	l_nEmptyDirStatus = (nFlags & WGEFF_EmptyAsNormal) ? WGFS_Normal : WGFS_Empty;

	l_bSkipNormalDirs = ((nFlags & (WGEFF_DirStatusDelta|WGEFF_DirStatusAll)) == WGEFF_DirStatusDelta);

	if (!(nFlags & WGEFF_SingleFile) && !l_bDirStatus)
	{
		// no recursive dir status requested, list all dirs as unknown
		l_bDirStatus = TRUE;
		l_nEmptyDirStatus = l_nMinStatusRelevantForDirs = WGFS_Unknown;
		l_bSkipNormalDirs = FALSE;
		l_dirTree.nStatus = WGFS_Unknown;
	}

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

	struct rev_info rev;
	init_revisions(&rev, prefix);
	rev.ignore_merges = 0;
	rev.no_walk = 1;
	rev.max_count = 1;
	l_bHasHistory = !setup_revisions_lite(&rev, "HEAD");

	read_cache();
	if (l_bHasHistory)
		preprocess_index(&rev);
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

		if (excluded(dir, ce->name, &dtype) != !!(dir->flags & DIR_SHOW_IGNORED))
			continue;
		if (ce->ce_flags & CE_UPDATE)
			continue;

		// skip file if not inside specified sub-path
		// this test was originally done in enum_ce_entry but in order to avoid unecessery lstat calls it was moved
		if (prefix_len >= ce_namelen(ce))
			die("git ls-files: internal error - cache entry not superset of prefix");
		if (pathspec && !match_pathspec(pathspec, ce->name, ce_namelen(ce), prefix_len, ps_matched))
			continue;

		if (single_dir || (no_recurse && is_subpath(refpath, pathspec_len, ce->name)))
		{
			if (l_bDirStatus)
				// this file would normally be skipped, but in order to determine correct dir status we need to process it
				update_dirs(ce, pathspec_len, FALSE);

			continue;
		}

		err = (ce->ce_flags & CE_IG_DELETED) ? 1 : lstat(ce->name, &st);

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

	BOOL bIgnoreInitialized = FALSE;

	if (pszSubPath)
	{
		// check if root (pszSubPath) dir is ignored

		if (!bIgnoreInitialized)
		{
			exc_given = 1;
			setup_standard_excludes(dir);
			bIgnoreInitialized = TRUE;
		}

		char sDir[MAX_PATH];
		strcpy(sDir, pszSubPath);
		LPSTR p = strrchr(sDir, '/');
		if (p) *p = 0;

		int dtype = DT_DIR;
		// check for matching ignore for each subdir level
		p = strchr(sDir, '/');
		for (;;)
		{
			if (p)
				*p = 0;

			if ( excluded(dir, sDir, &dtype) )
			{
				l_dirTree.nStatus = WGFS_Ignored;
				l_dirTree.bExplicitlyIgnored = TRUE;
			}

			if (p)
			{
				*p = '/';
				p = strchr(p+1, '/');
				if (!p)
					break;
			}
			else
			{
				break;
			}
		}
	}

	// enumerate unversioned files
	if ( !(nFlags & WGEFF_SingleFile) )
	{
		const char *path = ".", *base = "";
		int baselen = prefix_len;

		if (baselen)
			path = base = prefix;

		if (!bIgnoreInitialized)
		{
			exc_given = 1;
			setup_standard_excludes(dir);
			bIgnoreInitialized = TRUE;
		}
		dir->flags |= DIR_COLLECT_IGNORED;
		dir->flags &= ~DIR_SHOW_IGNORED;
		dir->flags &= ~DIR_SHOW_OTHER_DIRECTORIES;
		dir->flags &= ~DIR_HIDE_EMPTY_DIRECTORIES;
		dir->flags |= DIR_COLLECT_ALL_IGNORED;
		dir->flags |= DIR_COLLECT_DIRECTORIES;
		if (no_recurse)
			dir->flags |= DIR_NO_RECURSE_READDIR;
		else
			dir->flags &= ~DIR_NO_RECURSE_READDIR;
		read_directory(dir, path, base, baselen, pathspec);

		// if root dir is ignored, then all unversioned files under it are considered ignore
		enum_unversioned(dir->entries, dir->nr, l_dirTree.bExplicitlyIgnored);
		enum_unversioned(dir->ignored, dir->ignored_nr, TRUE);
	}
	else if (!single_dir && !l_nEnumeratedCached)
	{
		// get status of a single unversioned file

		if (!bIgnoreInitialized)
		{
			exc_given = 1;
			setup_standard_excludes(dir);
			bIgnoreInitialized = TRUE;
		}

		LPCSTR sFileName;

		if (!l_bFullPath)
		{
			sFileName = pszSubPath + prefix_offset;
		}
		else
		{
			strcpy(l_lpszFileName, pszSubPath);
			sFileName = l_sFullPathBuf;
		}

		int dtype = DT_REG;
		// if root dir is ignored, then all unversioned files under it are considered ignore
		if (!l_dirTree.bExplicitlyIgnored && excluded(dir, pszSubPath, &dtype))
			fputs("F I 0000000000000000000000000000000000000000 ", stdout);
		else
			fputs("F U 0000000000000000000000000000000000000000 ", stdout);
		fputs(sFileName, stdout);
		fputc(0, stdout);
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
			lpszRootDir = ".";

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
