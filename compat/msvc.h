#ifndef __MSVC__HEAD
#define __MSVC__HEAD

#include "msvc-posix.h"
#include "mingw.h"

/* Git runtime infomation */
#define RUNTIME_PREFIX
#define FALLBACK_RUNTIME_PREFIX ""
#define PREFIX "."
#define BINDIR "bin"

#define ETC_GITCONFIG "etc\\gitconfig"
#define ETC_GITATTRIBUTES "etc\\gitattributes"
#define GIT_EXEC_PATH "bin"
#define GIT_MAN_PATH "man"
#define GIT_INFO_PATH "info"
#define GIT_HTML_PATH "doc\\git\\html"
#define DEFAULT_GIT_TEMPLATE_DIR "share\\git-core\\templates"
#endif

/* Git version infomation */
#ifndef __MSVC__VERSION
#define __MSVC__VERSION
#define GIT_VERSION "2.50."
#define GIT_USER_AGENT "git/" GIT_VERSION
#define GIT_BUILT_FROM_COMMIT "(unknown)"
#endif
