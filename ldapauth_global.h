/*++

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:	ldapauth_global.h

	Abstract:
    Global compile time options.

	Modification History:

--*/

#ifndef _IISLDAPAUTH_GLOBAL_H_
#define _IISLDAPAUTH_GLOBAL_H_

/*
    Constants
*/
#define MAXSTRLEN			1024

/*
	Compile Options
*/
#ifdef _DEBUG
#define IISLDAPAUTH_DEBUG					1
#endif
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

#include "string_safe.h"

/*
	Logging routines are used globally
*/
#ifdef IISLDAPAUTH_FILE_LOG
#include "ldapauthlog.h"
#endif  /* IISLDAPAUTH_FILE_LOG */


#endif /*  _IISLDAPAUTH_GLOBAL_H_  */