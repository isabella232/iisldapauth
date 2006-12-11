/*++

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:	cache.h

	Abstract:
    This module implements a simple user cache.  The cached users are kept
    in an LRU sorted list.  If there will be a large number of simultaneous
    users, then a sorted array would be more appropriate.

	Modification History:

	2006-12-11 ramr
	File created.
--*/

#ifndef _IISLDAPAUTHCACHE_H_
#define _IISLDAPAUTHCACHE_H_
#include <httpfilt.h>

#define DEFAULT_CACHE_USERS     500
#define DEFAULT_CACHE_TIME		1800		/* 30 minutes */
#define MAX_CACHE_USERS			10000
#define MAX_CACHE_TIME			604800		/* 1 week */
#define HUNDRED_NS_FRACTION 	10000000

/*
    Cached user structure
*/

typedef struct SUSER_CACHE
{
    CHAR	m_achUserName[SF_MAX_USERNAME];		/* External username and password */
    CHAR	m_achPassword[SF_MAX_PASSWORD];
    CHAR	m_achNTUserName[SF_MAX_USERNAME];	/* Mapped NT account and password */
    CHAR	m_achNTUserPassword[SF_MAX_PASSWORD];
	UINT64	m_lliTimestamp;						/* Cache entry timestamp */
} SUSER_CACHE, *PUSER_CACHE;

BOOL
Cache_Initialize(
    const UINT32 kuliCacheSize,
	const UINT32 kuliCacheTime
    );

BOOL
Cache_GetUser(
    CHAR * pszUserName,
	BOOL * pfFound,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    );

BOOL
Cache_AddUser(
    CHAR * pszUserName,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    );

VOID
Cache_Terminate(
    VOID
    );

UINT64
GetSystemTime100ns( VOID );

#endif _IISLDAPAUTHCACHE_H_