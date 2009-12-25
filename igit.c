// igit.c
//
#include "git-compat-util.h"
#include <windows.h>
#include "igit.h"
#include "exec_cmd.h"
#include "git-compat-util.h"
#include "builtin.h"
#include "diff.h"
#include "revision.h"
#include <fcntl.h>
#include <stdlib.h>


#define IGIT_VERSION "0.1.0"


#define SAFE_FREE(_x) if (_x) { free(_x); _x = NULL; }

#define ASSERT(_x) //assert(_x)


static char l_sGitBinPath[2048];


/////////////////////////////////////////////////////////////////////
// Git utils

// GitCommandInit flags (mirrored from git.c)
#define RUN_SETUP		(1<<0)
#define USE_PAGER		(1<<1)
#define NEED_WORK_TREE	(1<<2)


// GitCommandInit - does the basic init of run_command in git.c (returns path relative to project root)
static const char* GitCommandInit(int flags)
{
	// simple init in main of git.c to set up git sys path
	char *prefix;
	git_extract_argv0_path(l_sGitBinPath);

	setup_path();

	// init from run_command

	prefix = NULL;

	if (flags & RUN_SETUP)
		prefix = setup_git_directory();

	if (flags & NEED_WORK_TREE)
		setup_work_tree();

	return prefix;
}


void fputsha1(LPBYTE sha1, FILE *fp)
{
	int i;
	for (i=0; i<20; i++)
	{
		fprintf(fp, "%02x", (UINT)*sha1++);
	}
}

/////////////////////////////////////////////////////////////////////
// igInitPath

static LPSTR nextpath(LPCSTR src, LPSTR dst, UINT maxlen)
{
	LPCSTR orgsrc;

	while (*src == ';')
		src++;

	orgsrc = src;

	if (!--maxlen)
		goto nullterm;

	while (*src && *src != ';')
	{
		if (*src != '"')
		{
			*dst++ = *src++;
			if (!--maxlen)
			{
				orgsrc = src;
				goto nullterm;
			}
		}
		else
		{
			src++;
			while (*src && *src != '"')
			{
				*dst++ = *src++;
				if (!--maxlen)
				{
					orgsrc = src;
					goto nullterm;
				}
			}

			if (*src)
				src++;
		}
	}

	while (*src == ';')
		src++;

nullterm:

	*dst = 0;

	return (orgsrc != src) ? (LPSTR)src : NULL;
}

static inline BOOL FileExists(LPCSTR lpszFileName)
{
	struct stat st;
	return lstat(lpszFileName, &st) == 0;
}

static BOOL FindGitPath()
{
	char *env;
	char buf[_MAX_PATH];
	const LPCSTR filename = "git.exe";
	const int filelen = strlen(filename);
	int len;

	if ( !(env = getenv("PATH")) )
	{
		return FALSE;
	}

	// search in all paths defined in PATH
	while ((env = nextpath(env, buf, _MAX_PATH-1)) && *buf)
	{
		char *pfin = buf + strlen(buf)-1;

		// ensure trailing slash
		if (*pfin != '/' && *pfin != '\\')
			strcpy(pfin+1, "\\");

		len = strlen(buf);

		if ((len + filelen) < _MAX_PATH)
			strcpy(buf+len, filename);
		else
			break;

		if ( FileExists(buf) )
		{
			// dir found
			memcpy(l_sGitBinPath, buf, len);
			l_sGitBinPath[len] = 0;
			return TRUE;
		}
	}

	return FALSE;
}


BOOL igInitPath(void)
{
	char *p;

	if ( !FindGitPath() )
	{
		// fallback and use path of libiconv2.dll which wingit is linked to and normally is located in the git dir
		if ( !GetModuleFileName(GetModuleHandle("libiconv2.dll"), l_sGitBinPath, sizeof(l_sGitBinPath)) )
		{
			OutputDebugString("[IGIT] Failed to locate Git/bin path\r\n");
			return FALSE;
		}
	}

	// slashify path to avoid mixing back and forward slashes (git uses forward)
	p = l_sGitBinPath;
	while (*p)
	{
		if (*p == '\\') *p = '/';
		p++;
	}

	return TRUE;
}


/////////////////////////////////////////////////////////////////////
// igEnumFiles - based on builtin-ls-files

extern BOOL ig_enum_files(const char *pszProjectPath, const char *pszSubPath, const char *prefix, unsigned int nFlags);


int igEnumFiles(const char *pszProjectPath, const char *pszSubPath, unsigned int nFlags)
{
	const char *prefix;

	// clean up subpath
	if (pszSubPath)
	{
		int len = strlen(pszSubPath);
		char *c;
		//char *s = alloca(len+1);
		//strcpy(s, pszSubPath);
		char *s = strdup(pszSubPath);

		// slashify
		char *p = s;
		while (*p)
		{
			if (*p == '\\') *p = '/';
			p++;
		}

		// remove trailing slashes
		c = &s[len-1];
		while (*c == '/' && c > s) *c-- = 0;
		// remove initial slashes
		while (*s == '/') s++;

		pszSubPath = *s ? s : NULL;
	}

	prefix = GitCommandInit(RUN_SETUP);

	if ( !ig_enum_files(pszProjectPath, pszSubPath, prefix, nFlags) )
	{
		return -1;
	}

	return 0;
}


/////////////////////////////////////////////////////////////////////
// igGetRevisionID

int igGetRevisionID(const char *pszName)
{
	BYTE sha1[20];

	GitCommandInit(0);

	git_config(git_default_config, NULL);

	if ( !get_sha1(pszName, sha1) )
	{
		fputsha1(sha1, stdout);
		fputc(0, stdout);

		return 0;
	}

	return -1;
}


/////////////////////////////////////////////////////////////////////
// main

int statusex_buildin(int argc, const char **argv)
{
	const char *projpath;
	const char *cmd;
	int res ;//= res;

	if (argc < 3)
	{
		if (argc == 2 && !strcasecmp(argv[1], "version"))
		{
			fputs(IGIT_VERSION, stdout);
			fputc(0, stdout);
			return 0;
		}

		fputs("igit v"IGIT_VERSION" - backend interface to git intended for use by frontends\n\n", stderr);
		fputs("usage: igit <project path> <command> [params]*\n", stderr);
		fputs("       igit version\n\n", stderr);
		fputs("commands:\n", stderr);
		fputs("    revision [name]           SHA1 for specified commit or HEAD if none\n", stderr);
		fputs("    status [flags [sub path]] list working copy files with status\n", stderr);
		fputs("                              flags: dDefrs-\n", stderr);
		return -1;
	}

	if ( !igInitPath() )
	{
		return -1;
	}

	//if (argv[0] && *argv[0])
	//	git_extract_argv0_path(argv[0]);
	git_extract_argv0_path(l_sGitBinPath);

	argv++;
	argc--;

	// get project path

	projpath = argv[0];

	if ( chdir(projpath) )
		return -1;

	argv++;
	argc--;

	// get command

	cmd = argv[0];

	argv++;
	argc--;

	// process command

	res = 0;

	if ( !strcasecmp(cmd, "revision") )
	{
		const char *name = argc ? argv[0] : "HEAD";

		res = igGetRevisionID(name);
	}
	else if ( !strcasecmp(cmd, "status") )
	{
		UINT nFlags = 0;
		LPCSTR pszSubPath = NULL;

		if (argc)
		{
			LPCSTR q = argv[0];
			while (*q)
			{
				switch (*q++)
				{
				case 'd': nFlags |= WGEFF_DirStatusDelta; break;
				case 'D': nFlags |= WGEFF_DirStatusAll; break;
				case 'e': nFlags |= WGEFF_EmptyAsNormal; break;
				case 'f': nFlags |= WGEFF_FullPath; break;
				case 'r': nFlags |= WGEFF_NoRecurse; break;
				case 's': nFlags |= WGEFF_SingleFile; break;
				}
			}

			if (argc > 1)
				pszSubPath = argv[1];
		}

		res = igEnumFiles(projpath, pszSubPath, nFlags);
	}

	return res;
}
