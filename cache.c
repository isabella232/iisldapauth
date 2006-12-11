/*

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:  cache.c

	Abstract:
    This module implements a simple user cache.  The cached users are kept
    in an LRU sorted list.  If there will be a large number of simultaneous
    users, then a sorted array would be more appropriate.

  	Modification History:

	2006-12-04 ramr
	Import into SourceForge CVS. Refer to CVS log for modification history.

	2002-04-22 ramr
    Made the cache actually work. Still sucks, need a real search/key
	algorithm like radix tree, etc. Since I only have a 1000 users,
	I really don't care.

--*/

#include "ldapauth.h"

/*
   Constants
*/

/*
    MAX_CACHED_USERS: The maximum number of users we will cache.  Change 
	this number if a large amount of simultaneous users are expected. If 
	the cache fills up, new users will not be cached.

	MAX_CACHE_TIME: Time limit until the cache entry is considered invalid.
*/

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

/*
    Globals

	gfCacheInitialized	- Indicates whether we are initialized
	guliCacheItems		- Number of items in the cache
	guliCacheSize		- Maximum number of user records in cache
	guliCacheTime		- Maximum lifetime (in seconds) for a cache entry
	gpCache				- Circular double linked list of cached users
	gsCacheLock			- Critical section protects cache list
*/

BOOL				gfCacheInitialized	= FALSE;
UINT32				guliCacheItems		= 0;
UINT32				guliCacheSize		= 0;
UINT32				guliCacheTime		= 0;
SUSER_CACHE			*gpCache			= NULL;
CRITICAL_SECTION	gsCacheLock			= {0};


BOOL
Cache_Initialize(
    const UINT32 kuliCacheSize,
	const UINT32 kuliCacheTime
    )
/*++

Routine Description:

    Initializes the cache module

Return Value:

    TRUE if initialized successfully, FALSE on error

--*/
{
    if ( gfCacheInitialized )
	{
        return gfCacheInitialized;
	}

	guliCacheSize = kuliCacheSize;
	guliCacheTime = kuliCacheTime;

	/*  Force some sane values.  */
	if ( 
		guliCacheSize > MAX_CACHE_USERS || 
		guliCacheSize < DEFAULT_CACHE_USERS 
	   )
	{
		guliCacheSize = DEFAULT_CACHE_USERS;
	}

	if ( guliCacheTime > MAX_CACHE_TIME )
	{
		guliCacheTime = DEFAULT_CACHE_TIME;
	}

    InitializeCriticalSection( &gsCacheLock );

    gpCache = LocalAlloc( LPTR, sizeof(SUSER_CACHE) * guliCacheSize );

	if ( gpCache != NULL )
	{
		gfCacheInitialized = TRUE;
	}

    return gfCacheInitialized;
}


BOOL
Cache_GetUser(
	BOOL * pfFound,
    CHAR * pszUserName,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    )
/*++

Routine Description:

    Checks to see if a user is in the cache and returns the user properties
    if found

Arguments:

    pszUserName			- Case insensitive username to find
    pfFound				- Set to TRUE if the specified user was found
    pszPassword			- Receives password for specified user if found
    pszNTUser			- Receives the NT Username to map this user to
    pszNTUserPassword	- Receives the NT Password for pszNTUser

    Note: pszPassword and pszNTUserPassword must be at least SF_MAX_PASSWORD
    characters.  pszNTUser must be at least SF_MAX_USERNAME characters.

Return Value:

    TRUE if no errors occurred.

--*/
{
	BOOL	fFound		= FALSE;
	UINT32	uliIndex	= 0;
	UINT32	uliSeconds	= 0;
	UINT64	ulliCurTime	= 0;
	UINT64	ulliDelta	= 0;
    
	/*
        Search the cache for the specified user
    */

    EnterCriticalSection( &gsCacheLock );

	*pfFound = FALSE;

	ulliCurTime = GetSystemTime100ns();

    while ( (uliIndex < guliCacheItems) && (!fFound) )
	{
        if ( !stricmp(pszUserName, gpCache[uliIndex].m_achUserName) ) 
		{
			if ( !stricmp(pszPassword, gpCache[uliIndex].m_achPassword) )
			{
				ulliDelta = ulliCurTime - gpCache[uliIndex].m_lliTimestamp;
				
				uliSeconds = (UINT32)(ulliDelta / HUNDRED_NS_FRACTION);
				
				if ( uliSeconds > guliCacheTime )
				{
					gpCache[uliIndex].m_lliTimestamp = 0;
					break;
				}

				fFound = TRUE;
			}
			else
			{
				gpCache[uliIndex].m_lliTimestamp = 0;
				break;				
			}
		}
		else
		{	
			uliIndex++;
		}
	}

	if ( !fFound )
	{	
		LeaveCriticalSection( &gsCacheLock );
		return TRUE;
	}
	else
	{
		/*
		    Copy out the user properties
		*/

		strlcpy( pszPassword,       gpCache[uliIndex].m_achPassword, SF_MAX_PASSWORD );
		strlcpy( pszNTUser,         gpCache[uliIndex].m_achNTUserName, SF_MAX_USERNAME );
		strlcpy( pszNTUserPassword, gpCache[uliIndex].m_achNTUserPassword, SF_MAX_PASSWORD );

		gpCache[uliIndex].m_lliTimestamp = ulliCurTime;

		LeaveCriticalSection( &gsCacheLock );
		
		*pfFound = TRUE;

		return TRUE;
	}
	
	return FALSE;
}


BOOL
Cache_AddUser(
    CHAR * pszUserName,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    )
/*++

Routine Description:

    Adds the specified user to the cache

Arguments:

    pszUserName			- Username to add
    pszPassword			- Contains the external password for this user
    pszNTUser			- Contains the NT user name to use for this user
    pszNTUserPassword	- Contains the password for gach_config_ntuser

Return Value:

    TRUE if no errors occurred.

--*/
{
	BOOL	fFound						= FALSE;
	CHAR	achNTUser[SF_MAX_USERNAME]	= "";
    CHAR	achNTPass[SF_MAX_PASSWORD]	= "";
	UINT32  uliIndex					= 0;
	UINT64	ulliCurTime					= 0;
	
	/*
        Check our parameters before adding them to the cache
    */

    if ( strlen(pszUserName) > SF_MAX_USERNAME ||
         strlen(pszPassword) > SF_MAX_PASSWORD ||
         strlen(pszNTUser) > SF_MAX_USERNAME ||
         strlen(pszNTUserPassword) > SF_MAX_PASSWORD )
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    /*
        Search the cache for the specified user to 
		make sure there are no duplicates
    */

    EnterCriticalSection( &gsCacheLock );

	ulliCurTime = GetSystemTime100ns();

	while ( uliIndex < guliCacheItems )
	{
		if ( gpCache[uliIndex].m_lliTimestamp == 0 )
		{
			break;
		}

		if ( ((ulliCurTime - gpCache[uliIndex].m_lliTimestamp) / HUNDRED_NS_FRACTION) > MAX_CACHE_TIME )
		{
			break;
		}

		uliIndex++;
	}

	if ( uliIndex == guliCacheItems && guliCacheItems < guliCacheSize )
	{	
		guliCacheItems++;
	}

	if ( uliIndex < guliCacheItems )
	{
		/*
		    Set the various fields
		*/

		strlcpy( gpCache[uliIndex].m_achUserName, pszUserName, SF_MAX_USERNAME );
		strlcpy( gpCache[uliIndex].m_achPassword, pszPassword, SF_MAX_PASSWORD );
		strlcpy( gpCache[uliIndex].m_achNTUserName, pszNTUser, SF_MAX_USERNAME );
		strlcpy( gpCache[uliIndex].m_achNTUserPassword, pszNTUserPassword, SF_MAX_PASSWORD );
		gpCache[uliIndex].m_lliTimestamp = ulliCurTime;
	}

	LeaveCriticalSection( &gsCacheLock );

    return TRUE;
}


VOID
Cache_Terminate(
    VOID
    )
/*++

Routine Description:

    Terminates the cache module and frees any allocated memory

--*/
{
    if ( !gfCacheInitialized )
	{
        return;
	}

    EnterCriticalSection( &gsCacheLock );

	LocalFree( gpCache );
	gpCache = NULL;
    guliCacheItems = 0;

    LeaveCriticalSection( &gsCacheLock );
    DeleteCriticalSection( &gsCacheLock );

    gfCacheInitialized = FALSE;
}


UINT64
GetSystemTime100ns( VOID )
{
	SYSTEMTIME		sSystemTime = { 0 };
	FILETIME		sFileTime	= { 0 };
	UINT64			llResult	= 0;

	GetLocalTime ( &sSystemTime );
	SystemTimeToFileTime( &sSystemTime, &sFileTime );

	llResult = (((UINT64)sFileTime.dwHighDateTime) << 32);
	llResult += sFileTime.dwLowDateTime;

	return llResult;
}