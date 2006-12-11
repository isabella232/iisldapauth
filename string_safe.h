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

	The functions in this file are not needed in VS2005 or later.

--*/

#ifndef _STRL_FUNCTIONS_
#define _STRL_FUNCTIONS_

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

#endif /* _STRL_FUNCTIONS_ */