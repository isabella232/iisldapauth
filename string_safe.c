/*

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:  string_safe.c

	Abstract:
    Visual Studio 2003 (or earlier) does not include new string
	manipulation functions with maximum buffer sizes. This is 
	essential to avoiding buffer overflow issues.

	The functions in this file are not needed in VS2005 or later.

--*/

#include <string.h>
#include "string_safe.h"

size_t
strlcpy(
		char *dst, 
		const char *src, 
		size_t size
		)
{
	strncpy( dst, src, size );
	return size;
}


size_t
strlcat(
		char *dst, 
		const char *src, 
		size_t size
		)
{
	size_t	src_size = 0;
	size_t	dst_size = 0;
	size_t	copy_size = 0;

	src_size = strlen( src );
	dst_size = strlen( dst );

	if ( (src_size + dst_size) < size )
	{
		strncat( dst, src, src_size );
		copy_size = src_size;
	}
/*  
	Total string size is too big. Only copy what will fit.
	It *is* possible that dst_size >= size, so check first.  
*/
	else if ( dst_size < size )
	{
		copy_size = size - dst_size;
		strncat( dst, src, copy_size );
	}

	return (dst_size + copy_size);
}