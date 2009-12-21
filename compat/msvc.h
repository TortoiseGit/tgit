#ifndef __MSVC__HEAD
#define __MSVC__HEAD

#include <direct.h>
#include <process.h>
#include <malloc.h>

/* porting function */
#define inline __inline
#define __inline__ __inline
#define __attribute__(x)
#define va_copy(dst, src)     ((dst) = (src))
#define strncasecmp  _strnicmp
#define ftruncate    _chsize

static __inline int strcasecmp (const char *s1, const char *s2)
{
	int size1 = strlen(s1);
	int sisz2 = strlen(s2);
	return _strnicmp(s1, s2, sisz2 > size1 ? sisz2 : size1);
}

#undef ERROR
#undef stat
#undef _stati64
#include "compat/mingw.h"
#undef stat
#define stat _stati64
#define _stat64(x,y) mingw_lstat(x,y)

/*
   Even though _stati64 is normally just defined at _stat64
   on Windows, we specify it here as a proper struct to avoid
   compiler warnings about macro redefinition due to magic in
   mingw.h. Struct taken from ReactOS (GNU GPL license).
*/
struct _stati64 {
	_dev_t  st_dev;
	_ino_t  st_ino;
	unsigned short st_mode;
	short   st_nlink;
	short   st_uid;
	short   st_gid;
	_dev_t  st_rdev;
	__int64 st_size;
	time_t  st_atime;
	time_t  st_mtime;
	time_t  st_ctime;
};

#define NO_PREAD
#define NO_OPENSSL
#define	NO_LIBGEN_H
#define	NO_SYMLINK_HEAD
#define	NO_IPV6
#define	NO_SETENV
#define	NO_UNSETENV
#define	NO_STRCASESTR
#define	NO_STRLCPY
#define	NO_MEMMEM
#define	NO_ICONV
#define	NO_C99_FORMAT
#define	NO_STRTOUMAX
#define	NO_STRTOULL
#define	NO_MKDTEMP
#define	NO_MKSTEMPS
#define	SNPRINTF_RETURNS_BOGUS
#define	NO_SVN_TESTS
#define	NO_PERL_MAKEMAKER 
#define	RUNTIME_PREFIX
#define	NO_POSIX_ONLY_PROGRAMS
#define	NO_ST_BLOCKS_IN_STRUCT_STAT
#define	NO_NSEC 
#define	USE_WIN32_MMAP
#define	UNRELIABLE_FSTAT 
#define	NO_REGEX
#define	NO_CURL
#define	NO_PTHREADS 

/*Git runtime infomation*/
#define ETC_GITCONFIG "%HOME%"
#define SHA1_HEADER "block-sha1\\sha1.h"
#define GIT_EXEC_PATH "bin"
#define GIT_VERSION "1.6.5"
#define BINDIR "bin"
#define PREFIX "."
#define GIT_MAN_PATH "man"
#define GIT_INFO_PATH "info"
#define GIT_HTML_PATH "html"
#define DEFAULT_GIT_TEMPLATE_DIR "templates"
#define GIT_USER_AGENT "git/1.6.5"
#endif
