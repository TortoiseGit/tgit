#include "cache.h"
#include "exec_cmd.h"
#include "quote.h"
#include <ShlObj.h>
#define MAX_ARGS	32

static const char *argv_exec_path;
static const char *argv0_path;

static int is_cygwin_hack_active()
{
	HKEY hKey;
	DWORD dwType = REG_DWORD;
	DWORD dwValue = 0;
	DWORD dwSize = sizeof(dwValue);
	if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\TortoiseGit", NULL, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
	{
		RegQueryValueExW(hKey, L"CygwinHack", NULL, &dwType, &dwValue, &dwSize);
		RegCloseKey(hKey);
	}
	return dwValue == 1;
}

static const char* win_common_git_config_path()
{
	static const char *common_path = NULL;
	static int already_looked_up = 0;

	if (!already_looked_up)
	{
		char pointer[MAX_PATH];
		wchar_t wbuffer[MAX_PATH];

		already_looked_up = 1;

		// do not use shared windows-wide system config when cygwin hack is active
		if (is_cygwin_hack_active())
			return NULL;

		if (SHGetFolderPathW(NULL, CSIDL_COMMON_APPDATA, NULL, SHGFP_TYPE_CURRENT, wbuffer) != S_OK || wcslen(wbuffer) >= MAX_PATH - 11) /* 11 = len("\\Git\\config") */
			return NULL;

		wcscat(wbuffer, L"\\Git\\config");

		if (_waccess(wbuffer, F_OK))
			return NULL;

		xwcstoutf(pointer, wbuffer, MAX_PATH);

		common_path = xstrdup(pointer);
	}

	return common_path;
}

char *system_path(const char *path)
{
	static const char *syspath = NULL;
	static DWORD dwMsys2Hack = 0;
	static DWORD dwCygwinHack = 0;

	if (is_absolute_path(path))
		return xstrdup(path);

	if (!syspath)
	{
		wchar_t lszValue[MAX_PATH];
		HKEY hKey;
		DWORD dwType = REG_SZ;
		DWORD dwSize = MAX_PATH;
		if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\TortoiseGit", NULL, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS)
		{
			if (RegQueryValueExW(hKey, L"MSysGit", NULL, &dwType, (LPBYTE)&lszValue, &dwSize) == ERROR_SUCCESS)
			{
				char pointer[MAX_PATH];
				xwcstoutf(pointer, lszValue, MAX_PATH);
				syspath = strip_path_suffix(pointer, "cmd");
				if (!syspath)
					syspath = strip_path_suffix(pointer, GIT_EXEC_PATH);

				do
				{
					char* configpath;
#ifdef _WIN64
					configpath = mkpath("%s\\mingw64", syspath);
					if (!access(configpath, F_OK))
					{
						free(syspath);
						syspath = xstrdup(configpath);
						break;
					}
#endif
					configpath = mkpath("%s\\mingw32", syspath);
					if (!access(configpath, F_OK))
					{
						free(syspath);
						syspath = xstrdup(configpath);
					}
				} while (FALSE);

				dwType = REG_DWORD;
				dwSize = sizeof(DWORD);
				if (RegQueryValueExW(hKey, L"Msys2Hack", NULL, &dwType, (LPBYTE)&dwMsys2Hack, &dwSize) == ERROR_SUCCESS && dwMsys2Hack)
				{
					// for Msys2 the system config is in etc folder, but git.exe is in usr/bin - we also need to strip usr
					const char *oldsyspath = syspath;
					syspath = strip_path_suffix(oldsyspath, "usr");
					free(oldsyspath);
				}
				RegQueryValueExW(hKey, L"CygwinHack", NULL, &dwType, (LPBYTE)&dwCygwinHack, &dwSize);
			}
			RegCloseKey(hKey);
		}
	}

	if (!strcmp(path, ETC_GITCONFIG) && !(dwMsys2Hack || dwCygwinHack))
	{
		const char* configpath = mkpath("%s\\%s", syspath, path);
		//if (!access(configpath, F_OK))
		//	return xstrdup(configpath);

		// check shared %PROGRAMDATA%\Git folder last, as we don't know if we're using a portable git
		if ((configpath = win_common_git_config_path()) != NULL)
			return configpath; // no need to strdup as we have a sattic buffer in win_common_git_config_path()
	}

	return xstrdup(mkpath("%s\\%s", syspath, path));
}

const char *git_extract_argv0_path(const char *argv0)
{
	const char *slash;

	if (!argv0 || !*argv0)
		return NULL;
	slash = argv0 + strlen(argv0);

	while (argv0 <= slash && !is_dir_sep(*slash))
		slash--;

	if (slash >= argv0) {
		argv0_path = xstrndup(argv0, slash - argv0);
		return slash + 1;
	}

	return argv0;
}

void git_set_argv_exec_path(const char *exec_path)
{
	argv_exec_path = exec_path;
	/*
	 * Propagate this setting to external programs.
	 */
	setenv(EXEC_PATH_ENVIRONMENT, exec_path, 1);
}


/* Returns the highest-priority, location to look for git programs. */
const char *git_exec_path(void)
{
	const char *env;

	if (argv_exec_path)
		return argv_exec_path;

	env = getenv(EXEC_PATH_ENVIRONMENT);
	if (env && *env) {
		return env;
	}

	return system_path(GIT_EXEC_PATH);
}

static void add_path(struct strbuf *out, const char *path)
{
	if (path && *path) {
		strbuf_add_absolute_path(out, path);
		strbuf_addch(out, PATH_SEP);
	}
}

void setup_path(void)
{
	const char *old_path = getenv("PATH");
	struct strbuf new_path = STRBUF_INIT;

	add_path(&new_path, git_exec_path());

	if (old_path)
		strbuf_addstr(&new_path, old_path);
	else
		strbuf_addstr(&new_path, _PATH_DEFPATH);

	setenv("PATH", new_path.buf, 1);

	strbuf_release(&new_path);
}

const char **prepare_git_cmd(const char **argv)
{
	int argc;
	const char **nargv;

	for (argc = 0; argv[argc]; argc++)
		; /* just counting */
	nargv = xmalloc(sizeof(*nargv) * (argc + 2));

	nargv[0] = "git";
	for (argc = 0; argv[argc]; argc++)
		nargv[argc + 1] = argv[argc];
	nargv[argc + 1] = NULL;
	return nargv;
}

int execv_git_cmd(const char **argv) {
	const char **nargv = prepare_git_cmd(argv);
	trace_argv_printf(nargv, "trace: exec:");

	/* execvp() can only ever return if it fails */
	sane_execvp("git", (char **)nargv);

	trace_printf("trace: exec failed: %s\n", strerror(errno));

	free(nargv);
	return -1;
}


int execl_git_cmd(const char *cmd,...)
{
	int argc;
	const char *argv[MAX_ARGS + 1];
	const char *arg;
	va_list param;

	va_start(param, cmd);
	argv[0] = cmd;
	argc = 1;
	while (argc < MAX_ARGS) {
		arg = argv[argc++] = va_arg(param, char *);
		if (!arg)
			break;
	}
	va_end(param);
	if (MAX_ARGS <= argc)
		return error("too many args to run %s", cmd);

	argv[argc] = NULL;
	return execv_git_cmd(argv);
}
