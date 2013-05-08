#ifndef __MSVC__HEAD
#define __MSVC__HEAD

#include <direct.h>
#include <process.h>
#include <malloc.h>
#include <io.h>

/* porting function */
#define inline __inline
#define __inline__ __inline
#define __attribute__(x)
#define strncasecmp  _strnicmp
#define ftruncate    _chsize
#define strtoull     _strtoui64
#define strtoll      _strtoi64

static __inline int strcasecmp (const char *s1, const char *s2)
{
	int size1 = strlen(s1);
	int sisz2 = strlen(s2);
	return _strnicmp(s1, s2, sisz2 > size1 ? sisz2 : size1);
}

#undef ERROR

#include "mingw.h"

/* Git runtime infomation */
#define SHA1_HEADER "block-sha1\\sha1.h"

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
#define GIT_VERSION "2.10.0"
#define GIT_USER_AGENT "git/" GIT_VERSION
#endif
