#ifndef __MSVC__HEAD
#define __MSVC__HEAD

#include <direct.h>
#include <process.h>
#include <malloc.h>
#include <io.h>

#pragma warning(disable: 4018) /* signed/unsigned comparison */
#pragma warning(disable: 4244) /* type conversion, possible loss of data */
#pragma warning(disable: 4090) /* 'function' : different 'const' qualifiers (ALLOC_GROW etc.)*/

/* porting function */
#define inline __inline
#define __inline__ __inline
#define __attribute__(x)
#define strcasecmp   _stricmp
#define strncasecmp  _strnicmp
#define ftruncate    _chsize
#define strtoull     _strtoui64
#define strtoll      _strtoi64

#undef ERROR

#define ftello _ftelli64

typedef int sigset_t;
/* open for reading, writing, or both (not in fcntl.h) */
#define O_ACCMODE     (_O_RDONLY | _O_WRONLY | _O_RDWR)

#include "mingw.h"

/* Git runtime infomation */
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
#define GIT_VERSION "2.21.0"
#define GIT_USER_AGENT "git/" GIT_VERSION
#define GIT_BUILT_FROM_COMMIT "(unknown)"
#endif
