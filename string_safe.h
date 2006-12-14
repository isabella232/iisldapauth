/*

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:  string_safe.h

	Abstract:
    Visual Studio 2003 (or earlier) does not include new string
	manipulation functions with maximum buffer sizes. This is 
	essential to avoiding buffer overflow issues.

	VS 2005 includes strlcpy() and strlcat(). The function
	strlreplace() is not included. To build with VS 2005,
	simply uncomment the #define VS2005 in ldapauth.h.

--*/

#ifndef _STRL_FUNCTIONS_
#define _STRL_FUNCTIONS_

#ifndef VS2005
size_t
strlcpy(
		char *dst, 
		const char *src, 
		size_t size
		);

size_t
strlcat(
		char *dst, 
		const char *src, 
		size_t size
		);
#endif /* VS2005 */

size_t 
strlreplace(
	char *dst, 
	char *search, 
	char *replace,
	size_t size
	);

#endif /* _STRL_FUNCTIONS_ */