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
#define USER_SEARCH_KEY		"%username%"

/*
	Compile Options
*/
#define IISLDAPAUTH_DEBUG					1
#define IISLDAPAUTH_DENYBLANKPASSWORDS		1
#define IISLDAPAUTH_CACHE					1
#define IISLDAPAUTH_FILE_LOG				1
/*
#define IISLDAPAUTH_BSTENTERPRISEHACK		1
*/

/*

	Visual Studio 2005 includes support for strlcpy() and strlcat().
	Enable the #define to turn off our versions of these routines.

#define VS2005				1
*/

/*
	Debug Strings
*/
#ifdef IISLDAPAUTH_FILE_LOG
#define DebugWrite( x ) Log_Write( x, LDAPLOG_DEBUG )
#else
#define DebugWrite( x )      /* nothing */
#endif /* IISLDAPAUTH_FILE_LOG */


/*
	Log entry cache
*/
typedef struct
{
    CHAR	m_achLDAPUser[SF_MAX_USERNAME];		/* LDAP username and password */
    CHAR	m_achNTUser[SF_MAX_USERNAME];		/* Mapped NT username and password */
	CHAR	m_achLogEntry[MAXSTRLEN];
} IISLDAPAUTH_CONTEXT;


/*
	Prototypes
*/

/*
	ISAPI routines
*/
BOOL
WINAPI
DllMain(
     HINSTANCE hinstDll,
     DWORD     fdwReason,
     LPVOID    lpvContext
     );

BOOL
WINAPI
GetFilterVersion(
	HTTP_FILTER_VERSION * pVer
    );

DWORD
WINAPI
HttpFilterProc(
    HTTP_FILTER_CONTEXT * pfc,
    DWORD NotificationType,
    VOID * pvData
    );

BOOL
ValidateUser(
    CHAR * pszUser,
    CHAR * pszPassword,
    BOOL * pfValid
    );

/*
	Database routines
*/
BOOL
LDAPDB_Initialize(
    VOID
    );

BOOL
LDAPDB_GetUser(
    CHAR * pszLDAPUser,
    BOOL * pfFound,
    CHAR * pszLDAPPassword,
    CHAR * pszNTUser,
    CHAR * pszNTPassword
    );

VOID
LDAPDB_Terminate(
    VOID
    );

/*
	Cache routines
*/
#ifdef IISLDAPAUTH_CACHE
#include "cache.h"
#endif  /* IISLDAPAUTH_CACHE */

/*
	Logging routines
*/
#ifdef IISLDAPAUTH_FILE_LOG
#include "ldapauthlog.h"
#endif  /* IISLDAPAUTH_FILE_LOG */

#endif /* _IISLDAPAUTH_H_ */