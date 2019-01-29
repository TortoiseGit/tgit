#include "cache.h"
#include "exec-cmd.h"
#include "quote.h"
#include "argv-array.h"

#if defined(RUNTIME_PREFIX)

#if defined(HAVE_NS_GET_EXECUTABLE_PATH)
#include <mach-o/dyld.h>
#endif

#if defined(HAVE_BSD_KERN_PROC_SYSCTL)
#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#endif

#endif /* RUNTIME_PREFIX */

#define MAX_ARGS 32

static const char *system_prefix(void);

/**
 * When using a runtime prefix, Git dynamically resolves paths relative to its
 * executable.
 *
 * The method for determining the path of the executable is highly
 * platform-specific.
 */

/**
 * Path to the current Git executable. Resolved on startup by
 * 'git_resolve_executable_dir'.
 */
static const char *executable_dirname;

static const char *system_prefix(void)
{
	static const char *syspath = NULL;

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
				DWORD dwMsys2Hack = 0;
				char pointer[MAX_PATH];
				xwcstoutf(pointer, lszValue, MAX_PATH);
				syspath = strip_path_suffix(pointer, "cmd");
				if (!syspath)
					syspath = strip_path_suffix(pointer, GIT_EXEC_PATH);

				do {
					const char *configpath;
#ifdef _WIN64
					configpath = mkpathdup("%s\\mingw64", syspath);
					if (!access(configpath, F_OK)) {
						free(syspath);
						syspath = configpath;
						break;
					}
					free(configpath);
#endif
					configpath = mkpathdup("%s\\mingw32", syspath);
					if (!access(configpath, F_OK)) {
						free(syspath);
						syspath = configpath;
						break;
					}
					free(configpath);
				} while (FALSE);

				dwType = REG_DWORD;
				dwSize = sizeof(DWORD);
				if (RegQueryValueExW(hKey, L"Msys2Hack", NULL, &dwType,(LPBYTE)&dwMsys2Hack,&dwSize) == ERROR_SUCCESS && dwMsys2Hack) {
					// for Msys2 the system config is in etc folder, but git.exe is in usr/bin - we also need to strip usr
					const char *oldsyspath = syspath;
					syspath = strip_path_suffix(oldsyspath, "usr");
					free(oldsyspath);
				}
			}
			RegCloseKey(hKey);
		}
	}

	return syspath;
}

/*
 * Resolves the executable path from argv[0], only if it is absolute.
 *
 * Returns 0 on success, -1 on failure.
 */
static int git_get_exec_path_from_argv0(struct strbuf *buf, const char *argv0)
{
	const char *slash;

	if (!argv0 || !*argv0)
		return -1;

	slash = find_last_dir_sep(argv0);
	if (slash) {
		trace_printf("trace: resolved executable path from argv0: %s\n",
			     argv0);
		strbuf_add_absolute_path(buf, argv0);
		return 0;
	}
	return -1;
}

#ifdef PROCFS_EXECUTABLE_PATH
/*
 * Resolves the executable path by examining a procfs symlink.
 *
 * Returns 0 on success, -1 on failure.
 */
static int git_get_exec_path_procfs(struct strbuf *buf)
{
	if (strbuf_realpath(buf, PROCFS_EXECUTABLE_PATH, 0)) {
		trace_printf(
			"trace: resolved executable path from procfs: %s\n",
			buf->buf);
		return 0;
	}
	return -1;
}
#endif /* PROCFS_EXECUTABLE_PATH */

#ifdef HAVE_BSD_KERN_PROC_SYSCTL
/*
 * Resolves the executable path using KERN_PROC_PATHNAME BSD sysctl.
 *
 * Returns 0 on success, -1 on failure.
 */
static int git_get_exec_path_bsd_sysctl(struct strbuf *buf)
{
	int mib[4];
	char path[MAXPATHLEN];
	size_t cb = sizeof(path);

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = -1;
	if (!sysctl(mib, 4, path, &cb, NULL, 0)) {
		trace_printf(
			"trace: resolved executable path from sysctl: %s\n",
			path);
		strbuf_addstr(buf, path);
		return 0;
	}
	return -1;
}
#endif /* HAVE_BSD_KERN_PROC_SYSCTL */

#ifdef HAVE_NS_GET_EXECUTABLE_PATH
/*
 * Resolves the executable path by querying Darwin application stack.
 *
 * Returns 0 on success, -1 on failure.
 */
static int git_get_exec_path_darwin(struct strbuf *buf)
{
	char path[PATH_MAX];
	uint32_t size = sizeof(path);
	if (!_NSGetExecutablePath(path, &size)) {
		trace_printf(
			"trace: resolved executable path from Darwin stack: %s\n",
			path);
		strbuf_addstr(buf, path);
		return 0;
	}
	return -1;
}
#endif /* HAVE_NS_GET_EXECUTABLE_PATH */

#ifdef HAVE_WPGMPTR
/*
 * Resolves the executable path by using the global variable _wpgmptr.
 *
 * Returns 0 on success, -1 on failure.
 */
static int git_get_exec_path_wpgmptr(struct strbuf *buf)
{
	int len = wcslen(_wpgmptr) * 3 + 1;
	strbuf_grow(buf, len);
	len = xwcstoutf(buf->buf, _wpgmptr, len);
	if (len < 0)
		return -1;
	buf->len += len;
	return 0;
}
#endif /* HAVE_WPGMPTR */

/*
 * Resolves the absolute path of the current executable.
 *
 * Returns 0 on success, -1 on failure.
 */
static int git_get_exec_path(struct strbuf *buf, const char *argv0)
{
	/*
	 * Identifying the executable path is operating system specific.
	 * Selectively employ all available methods in order of preference,
	 * preferring highly-available authoritative methods over
	 * selectively-available or non-authoritative methods.
	 *
	 * All cases fall back on resolving against argv[0] if there isn't a
	 * better functional method. However, note that argv[0] can be
	 * used-supplied on many operating systems, and is not authoritative
	 * in those cases.
	 *
	 * Each of these functions returns 0 on success, so evaluation will stop
	 * after the first successful method.
	 */
	if (
#ifdef HAVE_BSD_KERN_PROC_SYSCTL
		git_get_exec_path_bsd_sysctl(buf) &&
#endif /* HAVE_BSD_KERN_PROC_SYSCTL */

#ifdef HAVE_NS_GET_EXECUTABLE_PATH
		git_get_exec_path_darwin(buf) &&
#endif /* HAVE_NS_GET_EXECUTABLE_PATH */

#ifdef PROCFS_EXECUTABLE_PATH
		git_get_exec_path_procfs(buf) &&
#endif /* PROCFS_EXECUTABLE_PATH */

#ifdef HAVE_WPGMPTR
		git_get_exec_path_wpgmptr(buf) &&
#endif /* HAVE_WPGMPTR */

		git_get_exec_path_from_argv0(buf, argv0)) {
		return -1;
	}

	if (strbuf_normalize_path(buf)) {
		trace_printf("trace: could not normalize path: %s\n", buf->buf);
		return -1;
	}

	return 0;
}

void git_resolve_executable_dir(const char *argv0)
{
	struct strbuf buf = STRBUF_INIT;
	char *resolved;
	const char *slash;

	if (git_get_exec_path(&buf, argv0)) {
		trace_printf(
			"trace: could not determine executable path from: %s\n",
			argv0);
		strbuf_release(&buf);
		return;
	}

	resolved = strbuf_detach(&buf, NULL);
	slash = find_last_dir_sep(resolved);
	if (slash)
		resolved[slash - resolved] = '\0';

	executable_dirname = resolved;
	trace_printf("trace: resolved executable dir: %s\n",
		     executable_dirname);
}

char *system_path(const char *path)
{
	struct strbuf d = STRBUF_INIT;

	if (is_absolute_path(path))
		return xstrdup(path);

	strbuf_addf(&d, "%s/%s", system_prefix(), path);
	return strbuf_detach(&d, NULL);
}

static const char *exec_path_value;

void git_set_exec_path(const char *exec_path)
{
	exec_path_value = exec_path;
	/*
	 * Propagate this setting to external programs.
	 */
	setenv(EXEC_PATH_ENVIRONMENT, exec_path, 1);
}

/* Returns the highest-priority location to look for git programs. */
const char *git_exec_path(void)
{
	if (!exec_path_value) {
		const char *env = getenv(EXEC_PATH_ENVIRONMENT);
		if (env && *env)
			exec_path_value = xstrdup(env);
		else
			exec_path_value = system_path(GIT_EXEC_PATH);
	}
	return exec_path_value;
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
	const char *exec_path = git_exec_path();
	const char *old_path = getenv("PATH");
	struct strbuf new_path = STRBUF_INIT;

	git_set_exec_path(exec_path);
	add_path(&new_path, exec_path);

	if (old_path)
		strbuf_addstr(&new_path, old_path);
	else
		strbuf_addstr(&new_path, _PATH_DEFPATH);

	setenv("PATH", new_path.buf, 1);

	strbuf_release(&new_path);
}

const char **prepare_git_cmd(struct argv_array *out, const char **argv)
{
	argv_array_push(out, "git");
	argv_array_pushv(out, argv);
	return out->argv;
}

int execv_git_cmd(const char **argv)
{
	struct argv_array nargv = ARGV_ARRAY_INIT;

	prepare_git_cmd(&nargv, argv);
	trace_argv_printf(nargv.argv, "trace: exec:");

	/* execvp() can only ever return if it fails */
	sane_execvp("git", (char **)nargv.argv);

	trace_printf("trace: exec failed: %s\n", strerror(errno));

	argv_array_clear(&nargv);
	return -1;
}

int execl_git_cmd(const char *cmd, ...)
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
		return error(_("too many args to run %s"), cmd);

	argv[argc] = NULL;
	return execv_git_cmd(argv);
}
