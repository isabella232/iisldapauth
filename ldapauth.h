/*++

Copyright (c) 1996  Microsoft Corporation

This program is released into the public domain for any purpose.


Module Name:

    authfilt.h

Abstract:

    This module contains the common definitions for the authentication filter
    sample

--*/

#ifndef _AUTHFILT_H_
#define _AUTHFILT_H_
#include <stdlib.h>
#include <stdio.h>

//
//  Constants
//

#define ISWHITE( ch )      ((ch) && ((ch) == ' ' || (ch) == '\t' ||  \
                            (ch) == '\n' || (ch) == '\r'))

#ifndef DEST
#define DEST               "c:\\filtredbg.txt"
/*void DebugWrite( char * x )     
	{                                    
    FILE *f;                        
	f=fopen(DEST,"a");             
    fprintf(f,"%s", x);               
    fclose( f);        
    }*/
//#else
#define DebugWrite( x )      /* nothing */
#endif


#define DENYBLANKPASSWORDS 1
#define BSTENTERPRISEHACK 1
#define LDAP_CACHE 1


typedef struct
{
    int	iLength;
    CHAR szLogEntry[ 2 * SF_MAX_USERNAME + 4 ];
} LDAP_AUTH_CONTEXT; 


//
//  Prototypes
//

//
//  Database routines
//

BOOL
InitializeUserDatabase(
    VOID
    );

BOOL
ValidateUser(
    CHAR * pszUserName,
    CHAR * pszPassword,
    BOOL * pfValid
    );

BOOL
LookupUserInDb(
    IN CHAR * pszUser,
    OUT BOOL * pfFound,
    OUT CHAR * pszPassword,
    OUT CHAR * pszNTUser,
    OUT CHAR * pszNTUserPassword
    );

VOID
TerminateUserDatabase(
    VOID
    );

//
//  Cache routines
//

#ifdef LDAP_CACHE

BOOL
InitializeCache(
    VOID
    );

BOOL
LookupUserInCache(
    CHAR * pszUserName,
    BOOL * pfFound,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    );

BOOL
AddUserToCache(
    CHAR * pszUserName,
    CHAR * pszPassword,
    CHAR * pszNTUser,
    CHAR * pszNTUserPassword
    );

VOID
TerminateCache(
    VOID
    );

UINT64
GetSystemTime100ns( VOID );

#endif  /* LDAP_CACHE */

#endif //_AUTHFILT_H_
