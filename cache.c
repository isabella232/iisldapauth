/*++

	Released under LGPL.

	Some portions Copyright (c) 1996  Microsoft Corporation
	This program is released into the public domain for any purpose.


	Module Name:

    cache.c

	Abstract:

    This module implements a simple user cache.  The cached users are kept
    in an LRU sorted list.  If there will be a large number of simultaneous
    users, then a sorted array would be more appropriate.

  	Modification History:

	2002-04-22 ramr

    Made the cache actually work. Still sucks, need a real search/key
	algorithm like radix tree, etc. Since I only have a 1000 users,
	I really don't care.

--*/

#include <windows.h>
#include <httpfilt.h>

#include "ldapauth.h"

//
// Constants
//

//
//  The maximum number of users we will cache.  If there will be a large number
//  of simultaneous users, bump this value
//

#define MAX_CACHED_USERS        500
#define MAX_CACHE_TIME			1800
#define HUNDRED_NS_FRACTION 	10000000

//
//  Cached user structure
//

typedef struct USER_CACHE
{
    CHAR	achUserName[SF_MAX_USERNAME];   // External username and password
    CHAR	achPassword[SF_MAX_PASSWORD];

    CHAR	achNTUserName[SF_MAX_USERNAME]; // NT account and password to map user to
    CHAR	achNTUserPassword[SF_MAX_PASSWORD];

	UINT64	llTimestamp;
} USER_CACHE, *PUSER_CACHE;


//
//  Globals
//

//
//  Circular double linked list of cached users
//

USER_CACHE *pCache;

//
//  Critical section protects cache list
//

CRITICAL_SECTION csCacheLock;

//
//  Indicates whether we are initialized
//

BOOL fCacheInitialized = FALSE;

//
//  Number of items in the cache
//

unsigned long cCacheItems = 0;


BOOL
InitializeCache(
    VOID
    )
/*++

Routine Description:

    Initializes the cache module

Return Value:

    TRUE if initialized successfully, FALSE on error

--*/
{
    if ( fCacheInitialized )
	{
        return fCacheInitialized;
	}

    InitializeCriticalSection( &csCacheLock );

    pCache = LocalAlloc( LPTR, sizeof(USER_CACHE) * MAX_CACHED_USERS );

	if ( pCache != NULL )
	{
		fCacheInitialized = TRUE;
	}

    return fCacheInitialized;
}


BOOL
LookupUserInCache(
    CHAR * pszUserName,
    BOOL * pfFound,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    )
/*++

Routine Description:

    Checks to see if a user is in the cache and returns the user properties
    if found

Arguments:

    pszUserName - Case insensitive username to find
    pfFound     - Set to TRUE if the specified user was found
    pszPassword - Receives password for specified user if found
    pszNTUser   - Receives the NT Username to map this user to
    pszNTUserPassword - Receives the NT Password for pszNTUser

    Note: pszPassword and pszNTUserPassword must be at least SF_MAX_PASSWORD
    characters.  pszNTUser must be at least SF_MAX_USERNAME characters.

Return Value:

    TRUE if no errors occurred.

--*/
{
	unsigned long	lIndex		= 0;
    USER_CACHE		*pUser		= 0;
    DWORD			cPosition	= 0;
	DWORD			lSeconds	= 0;
	BOOL			fFound		= FALSE;
	UINT64			llCurTime	= 0;
	UINT64			llDelta		= 0;

    //
    //  Search the cache for the specified user
    //

    EnterCriticalSection( &csCacheLock );

	*pfFound = FALSE;

	llCurTime = GetSystemTime100ns();

    while ( (lIndex < cCacheItems) && (!fFound) )
	{
        if ( !stricmp(pszUserName, pCache[lIndex].achUserName) ) 
		{
			if ( !stricmp(pszPassword, pCache[lIndex].achPassword) )
			{
				llDelta = llCurTime - pCache[lIndex].llTimestamp;
				
				lSeconds = (UINT32)(llDelta / HUNDRED_NS_FRACTION);
				
				if ( lSeconds > MAX_CACHE_TIME )
				{
					pCache[lIndex].llTimestamp = 0;
					break;
				}

				fFound = TRUE;
			}
			else
			{
				pCache[lIndex].llTimestamp = 0;
				break;				
			}
		}
		else
		{	
			lIndex++;
		}
	}

	if ( !fFound )
	{	
		LeaveCriticalSection( &csCacheLock );
		return TRUE;
	}
	else
	{
		//
		//  Copy out the user properties
		//

		strcpy( pszPassword,       pCache[lIndex].achPassword );
		strcpy( pszNTUser,         pCache[lIndex].achNTUserName );
		strcpy( pszNTUserPassword, pCache[lIndex].achNTUserPassword );

		pCache[lIndex].llTimestamp = llCurTime;

		LeaveCriticalSection( &csCacheLock );
		
		*pfFound = TRUE;

		return TRUE;
	}
	
	return FALSE;
}


BOOL
AddUserToCache(
    CHAR * pszUserName,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    )
/*++

Routine Description:

    Adds the specified user to the cache

Arguments:

    pszUserName - Username to add
    pszPassword - Contains the external password for this user
    pszNTUser   - Contains the NT user name to use for this user
    pszNTUserPassword - Contains the password for NTUser

Return Value:

    TRUE if no errors occurred.

--*/
{

	BOOL	fFound						= FALSE;
	UINT32  lIndex				= 0;
	CHAR	achNTUser[SF_MAX_USERNAME]	= "";
    CHAR	achNTPass[SF_MAX_PASSWORD]	= "";
	UINT64	llCurTime					= 0;
	//
    //  Check our parameters before adding them to the cache
    //

    if ( strlen( pszUserName ) > SF_MAX_USERNAME ||
         strlen( pszPassword ) > SF_MAX_PASSWORD ||
         strlen( pszNTUser   ) > SF_MAX_USERNAME ||
         strlen( pszNTUserPassword ) > SF_MAX_PASSWORD )
    {
        SetLastError( ERROR_INVALID_PARAMETER );
        return FALSE;
    }

    //
    //  Search the cache for the specified user to make sure there are no
    //  duplicates
    //

    EnterCriticalSection( &csCacheLock );

	llCurTime = GetSystemTime100ns();

	while ( lIndex < cCacheItems )
	{
		if ( pCache[lIndex].llTimestamp == 0 )
		{
			break;
		}

		if ( ((llCurTime - pCache[lIndex].llTimestamp) / HUNDRED_NS_FRACTION) > MAX_CACHE_TIME )
		{
			break;
		}

		lIndex++;
	}

	if ( lIndex == cCacheItems && cCacheItems < MAX_CACHED_USERS )
	{	
		cCacheItems++;
	}

	if ( lIndex < cCacheItems )
	{

		//
		//  Set the various fields
		//

		strcpy( pCache[lIndex].achUserName,       pszUserName );
		strcpy( pCache[lIndex].achPassword,       pszPassword );
		strcpy( pCache[lIndex].achNTUserName,     pszNTUser );
		strcpy( pCache[lIndex].achNTUserPassword, pszNTUserPassword );
		pCache[lIndex].llTimestamp = llCurTime;
	}

	LeaveCriticalSection( &csCacheLock );

    return TRUE;
}


VOID
TerminateCache(
    VOID
    )
/*++

Routine Description:

    Terminates the cache module and frees any allocated memory

--*/
{
    if ( !fCacheInitialized )
	{
        return;
	}

    EnterCriticalSection( &csCacheLock );

	LocalFree( pCache );
	pCache = NULL;
    cCacheItems = 0;

    LeaveCriticalSection( &csCacheLock );

    DeleteCriticalSection( &csCacheLock );

    fCacheInitialized = FALSE;
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