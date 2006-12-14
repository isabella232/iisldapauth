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

	VS 2005 includes strlcpy() and strlcat(). The function
	strlreplace() is not included. To build with VS 2005,
	simply uncomment the #define VS2005 in ldapauth.h.

--*/

#include <stdlib.h>
#include <string.h>
#include "string_safe.h"

#ifndef VS2005
size_t
strlcpy(
		char *dst, 
		const char *src, 
		size_t size
		)
{
	size_t cpy_size = 0;

	if ( size == 0 ) goto exception;

	cpy_size = strlen( src );

	if ( !(cpy_size < size) )
	{
		/*  
			Add +1 for terminating byte. Assuming size_t is
			unsigned so -1 is safe. 
		*/
		cpy_size = size - 1;  
	}

	strncpy( dst, src, cpy_size );
	
	/*  
		Terminate string. Size cpy_size is likely the same
		length as the string, strncat() will not automatically
		append a terminating byte if cpy_size = strlen().
		
		Note cpy_size is actual characters copied and the buffer 
		is zero-index counted.
	*/
	dst[cpy_size] = 0;

exception:
	return ( cpy_size );
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
		strncat( dst, src, src_size );		/*  strncat() will terminate string  */
		copy_size = src_size;
	}
/*  
	Total string size is too big. Only copy what will fit.
	It *is* possible that dst_size >= size, so check first.  
*/
	else if ( dst_size < size )
	{
		copy_size = size - dst_size - 1;	/*  -1 for terminating byte  */
		
		if ( copy_size > 0 )
		{
			strncat( dst, src, copy_size );
		}
	}

	return ( dst_size + copy_size );
}
#endif /* #ifndef VS2005 */


size_t 
strlreplace(
	char *dst, 
	char *search, 
	char *replace,
	size_t size) 
/*++

Routine Description:

    Replaces all instances of a string inside a string with another
	string. 
	
	This routine has several complicated issues. First, we cannot modify 
	the parameter dst unless we will succeed. Second, strcpy() cannot be
	used to move parts of the same string around.

Arguments:

    dst		- destination string
    search	- search string
    replace	- replacement string
	size	- the maximum size of the dst string

Return Value:

    The length of the dst string with replacements.

--*/
{
	unsigned int	dst_len			= 0;	/*  length of the original dst parameter  */
	unsigned int	cur_len			= 0;	/*  current length of the dst with replacements  */
	unsigned int	search_len		= 0;	/*  length of the search string  */
	unsigned int	replace_len		= 0;	/*  length of the replacement string  */
	unsigned int	cpy_len			= 0;	/*  amount to copy  */
	unsigned int	replace_count	= 0;	/*  number of occurrances of search found  */
	char			*dst_copy		= NULL;	/*  memory buffer for a copy of dst  */
	char			*dst_ptr		= NULL; /*	pointer to the current lcoation in dst  */
	char			*dst_copy_ptr	= NULL; /*  pointer to the current location in dst_copy  */
	char			*start_ptr		= NULL; /*  pointer to the start of the next occurrance of search  */

	if ( dst == NULL || search == NULL || replace == NULL || size == 0 )
	{
		/*  Check for invalid parameters.  */
		goto exception;
	}

	dst_len = strlen( dst );
	replace_len = strlen( replace );
	search_len = strlen( search );

	if ( replace_len >= size )
	{
		/*  If replace_len is >= size, the operation can never work.  */
		goto exception;
	}

	cur_len = dst_len;
	
	/*  Make a working copy of the string. (+1 for terminator byte)  */
	dst_copy = malloc( dst_len + 1 );
	if ( dst_copy == NULL )
	{
		goto exception;
	}
	/*  strcpy() will not terminate string as dst_len is the string length  */
	strncpy( dst_copy, dst, dst_len );
	dst_copy[dst_len] = 0;

	/*
		Step 1: Find out how many occurances are there.
	*/
	start_ptr = dst_copy;
	while( (start_ptr = strstr(start_ptr, search)) != NULL )
	{
		replace_count++;
		start_ptr += search_len;
	}

	/*  Step 2: Check length of the new string with replacements.  */
	if ( (dst_len - (replace_count * search_len) + (replace_count * replace_len)) >= size )
	{
		/*  too big? don't even bother...  */
		goto exception;
	}

	/*  Start the replace operation  */
	dst_ptr = dst;
	dst_copy_ptr = dst_copy;

	start_ptr = strstr( dst_copy, search );
	while( (cur_len + 1) < size && start_ptr != NULL )
	{
		/*  Replace Step 1: Copy left size (from last occurrance to this one)  */
		cpy_len = start_ptr - dst_copy_ptr;
		strncpy( dst_ptr, dst_copy_ptr, cpy_len );

		/*  
			Move the indexes:
			dst_copy --> point after search  
		*/
		dst_ptr += cpy_len;
		dst_copy_ptr += (cpy_len + search_len);
		
		/*
			Replace Step 2:  Insert replace string.
		*/
		strncpy( dst_ptr, replace, replace_len );
		
		/*  
			Move the indexes:
			dst_ptr --> point after replace
		*/
		dst_ptr += replace_len;
		cur_len = dst_ptr - dst;

		/* Check for another pattern match */
		start_ptr = (char *)strstr( dst_copy_ptr, search );
	}

	/*
		Replace Final Step: Copy the rest of the string
		after the last occurrance of search.
	*/
	
	cpy_len = dst_len - (dst_copy_ptr - dst_copy);
	if ( cpy_len > 0 )
	{
		strncpy( dst_ptr, dst_copy_ptr, cpy_len );		
		cur_len += cpy_len;
	}

	/*  Terminate  */
	dst[cur_len] = 0;

exception:
	if ( dst_copy != NULL )
	{
		free( dst_copy );
	}

	return ( cur_len );
}