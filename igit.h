// igit.h

#ifndef _IGIT_H_
#define _IGIT_H_

#include <stdio.h>


// Flags for igEnumFiles
enum WGENUMFILEFLAGS
{
	WGEFF_NoRecurse		= (1<<0),	// only enumerate files directly in the specified path
	WGEFF_FullPath		= (1<<1),	// enumerated filenames are specified with full path (instead of relative to proj root)
	WGEFF_DirStatusDelta= (1<<2),	// include directories, in enumeration, that have a recursive status != WGFS_Normal (may have a slightly better performance than WGEFF_DirStatusAll)
	WGEFF_DirStatusAll	= (1<<3),	// include directories, in enumeration, with recursive status
	WGEFF_EmptyAsNormal	= (1<<4),	// report sub-directories, with no versioned files, as WGFS_Normal instead of WGFS_Empty
	WGEFF_SingleFile	= (1<<5),	// indicates that the status of a single file or dir, specified by pszSubPath, is wanted
	WGEFF_NoCacheIndex  = (1<<6)
};

// NOTE: Special behavior for directories when specifying WGEFF_SingleFile:
//
//       * when combined with WGEFF_SingleFile the returned status will only reflect the immediate files in the dir,
//         NOT the recusrive status of immediate sub-dirs
//       * unlike a normal enumeration where the project root dir always is returned as WGFS_Normal regardless
//         of WGEFF_EmptyAsNormal, the project root will return WGFS_Empty if no immediate versioned files
//         unless WGEFF_EmptyAsNormal is specified
//       * WGEFF_DirStatusDelta and WGEFF_DirStatusAll are ignored and can be omitted even for dirs


// File status
enum WGFILESTATUS
{
	WGFS_Normal,
	WGFS_Staged,
	WGFS_Added,
	WGFS_Deleted,
	WGFS_Modified,
	WGFS_Conflicted,

	WGFS_Ignored = -1,
	WGFS_Unversioned = -2,
	WGFS_Empty = -3,
	WGFS_Unknown = -4
};


// File flags
enum WGFILEFLAGS
{
	WGFF_Directory		= (1<<0)	// enumerated file is a directory
};


void fputsha1(LPBYTE sha1, FILE *fp);


#endif
