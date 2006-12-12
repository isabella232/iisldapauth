/*++

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:	ldapauth.h

	Abstract:
    Contains header information and definitions for the LDAP auth filter.

	Modification History:

--*/

#ifndef _IISLDAPAUTH_H_
#define _IISLDAPAUTH_H_
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <httpfilt.h>
#include "string_safe.h"

/*
    Constants
*/
#define MAXSTRLEN			1024
#define MODULE_CONF_FILE	"\\ldapauth.ini"	/*  Include beginning backslash  */
#define DEFAULTUID			"uid"

/*
	Compile Options
*/
#define DENYBLANKPASSWORDS	1
#define BSTENTERPRISEHACK	1
#define LDAP_CACHE			1
#define LDAP_LOGGING		1

/*
	Debug Strings
*/
#ifdef LDAP_LOGGING
#define DebugWrite( x ) Log_Write( x, LDAPLOG_DEBUG )
#else
#define DebugWrite( x )      /* nothing */
#endif /* LDAP_LOGGING */


typedef struct
{
    int	iLength;
    CHAR szLogEntry[ 2 * SF_MAX_USERNAME + 4 ];
} LDAP_AUTH_CONTEXT;


/*
	Prototypes
*/

/*
	Database routines
*/
BOOL
ValidateUser(
    CHAR * pszUserName,
    CHAR * pszPassword,
    BOOL * pfValid
    );

BOOL
LDAPDB_Initialize(
    VOID
    );

BOOL
LDAPDB_GetUser(
    IN CHAR * pszUser,
    OUT BOOL * pfFound,
    OUT CHAR * pszPassword,
    OUT CHAR * pszNTUser,
    OUT CHAR * pszNTUserPassword
    );

VOID
LDAPDB_Terminate(
    VOID
    );

/*
	Cache routines
*/
#ifdef LDAP_CACHE
#include "cache.h"
#endif  /* LDAP_CACHE */

/*
	Logging routines
*/
#ifdef LDAP_LOGGING
#include "ldapauthlog.h"
#endif  /* LDAP_LOGGING */

#endif /* _IISLDAPAUTH_H_ */
