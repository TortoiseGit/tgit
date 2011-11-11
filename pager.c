#include "cache.h"
#include "config.h"
#include "run-command.h"
#include "sigchain.h"
#include "alias.h"

#ifndef DEFAULT_PAGER
#define DEFAULT_PAGER "less"
#endif

static struct child_process pager_process = CHILD_PROCESS_INIT;
static const char *pager_program;

static void wait_for_pager(int in_signal)
{
	if (!in_signal) {
		fflush(stdout);
		fflush(stderr);
	}
	/* signal EOF to pager */
	close(1);
	close(2);
	if (in_signal)
		finish_command_in_signal(&pager_process);
	else
		finish_command(&pager_process);
}

static void wait_for_pager_atexit(void)
{
	wait_for_pager(0);
}

static void wait_for_pager_signal(int signo)
{
	wait_for_pager(1);
	sigchain_pop(signo);
	raise(signo);
}

static int core_pager_config(const char *var, const char *value, void *data)
{
	if (!strcmp(var, "core.pager"))
		return git_config_string(&pager_program, var, value);
	return 0;
}

const char *git_pager(int stdout_is_tty)
{
	return NULL;
}

static void setup_pager_env(struct argv_array *env)
{
	const char **argv;
	int i;
	char *pager_env = xstrdup(PAGER_ENV);
	int n = split_cmdline(pager_env, &argv);

	if (n < 0)
		die("malformed build-time PAGER_ENV: %s",
			split_cmdline_strerror(n));

	for (i = 0; i < n; i++) {
		char *cp = strchr(argv[i], '=');

		if (!cp)
			die("malformed build-time PAGER_ENV");

		*cp = '\0';
		if (!getenv(argv[i])) {
			*cp = '=';
			argv_array_push(env, argv[i]);
		}
	}
	free(pager_env);
	free(argv);
}

void prepare_pager_args(struct child_process *pager_process, const char *pager)
{
	argv_array_push(&pager_process->args, pager);
	pager_process->use_shell = 1;
	setup_pager_env(&pager_process->env_array);
}

void setup_pager(void)
{
	const char *pager = git_pager(isatty(1));

	if (!pager)
		return;

	/*
	 * After we redirect standard output, we won't be able to use an ioctl
	 * to get the terminal size. Let's grab it now, and then set $COLUMNS
	 * to communicate it to any sub-processes.
	 */
	{
		char buf[64];
		xsnprintf(buf, sizeof(buf), "%d", term_columns());
		setenv("COLUMNS", buf, 0);
	}

	setenv("GIT_PAGER_IN_USE", "true", 1);

	/* spawn the pager */
	prepare_pager_args(&pager_process, pager);
	pager_process.in = -1;
	argv_array_push(&pager_process.env_array, "GIT_PAGER_IN_USE");
	if (start_command(&pager_process))
		return;

	/* original process continues, but writes to the pipe */
	dup2(pager_process.in, 1);
	if (isatty(2))
		dup2(pager_process.in, 2);
	close(pager_process.in);

	/* this makes sure that the parent terminates after the pager */
	sigchain_push_common(wait_for_pager_signal);
	atexit(wait_for_pager_atexit);
}

int pager_in_use(void)
{
	return 0;
}

/*
 * Return cached value (if set) or $COLUMNS environment variable (if
 * set and positive) or ioctl(1, TIOCGWINSZ).ws_col (if positive),
 * and default to 80 if all else fails.
 */
int term_columns(void)
{
	static int term_columns_at_startup;

	char *col_string;
	int n_cols;

	if (term_columns_at_startup)
		return term_columns_at_startup;

	term_columns_at_startup = 80;

	col_string = getenv("COLUMNS");
	if (col_string && (n_cols = atoi(col_string)) > 0)
		term_columns_at_startup = n_cols;
#ifdef TIOCGWINSZ
	else {
		struct winsize ws;
		if (!ioctl(1, TIOCGWINSZ, &ws) && ws.ws_col)
			term_columns_at_startup = ws.ws_col;
	}
#endif

	return term_columns_at_startup;
}

/*
 * How many columns do we need to show this number in decimal?
 */
int decimal_width(uintmax_t number)
{
	int width;

	for (width = 1; number >= 10; width++)
		number /= 10;
	return width;
}

struct pager_command_config_data {
	const char *cmd;
	int want;
	char *value;
};

static int pager_command_config(const char *var, const char *value, void *vdata)
{
	return 0;
}

/* returns 0 for "no pager", 1 for "use pager", and -1 for "not specified" */
int check_pager_config(const char *cmd)
{
	return 0;
}
