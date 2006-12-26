/*

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:	db.c

	Abstract:	
	This module implements the database routines for the authentication filter.

	Modification History:

	2006-12-04 ramr
	Import into SourceForge CVS. Refer to CVS log for modification history.

    2002-11-24 ramr
    Changed config file parsing to support comments.

	2002-04-22 ramr
    Cleaned up LDAP code, added non-SSL support.

*/

#include <stdio.h>
#include ".\novell-cldap\Win32\inc\ldap.h"
#include ".\novell-cldap\Win32\inc\ldap_ssl.h"
#include ".\novell-cldap\Win32\inc\lber.h"
#include "ldapauth.h"

/*
	Global Configuration Variables
	These are read from the ldapauth.ini file.
*/

BOOL	gf_SSL_client_init						= FALSE;
INT16	gi_config_ldapport						= 0;
CHAR	gach_config_binduser[MAXSTRLEN]			= "";
CHAR	gach_config_bindpassword[MAXSTRLEN]		= "";
CHAR	gach_config_ldaphost[MAXSTRLEN]			= "";
CHAR	gach_config_ldapfilter[MAXSTRLEN]		= "";
CHAR	gach_config_searchbase[MAXSTRLEN]		= "";
CHAR	gach_config_certsfile[MAXSTRLEN]		= "";
INT32	gli_config_certsfileformat				= LDAPSSL_CERT_FILETYPE_B64;
CHAR	gach_config_ntuser[MAXSTRLEN]			= "";
CHAR	gach_config_ntuserpassword[MAXSTRLEN]	= "";
#ifdef IISLDAPAUTH_CACHE
UINT32	guli_config_cachesize					= 0;
UINT32	guli_config_cachetime					= 0;
#endif

BOOL
LDAPDB_Initialize(
    VOID
    )
/*++

Routine Description:

	Reads %SYSTEMROOT%\ldapauth.ini for configuration values.

Return Value:

    TRUE on success, FALSE on failure.

--*/
{
    BOOL	bResult							= FALSE;
	FILE	*pfs							= 0; 
	CHAR	achLine[MAXSTRLEN]				= "";
	CHAR	achToken[MAXSTRLEN]				= "";
	CHAR	achParam[MAXSTRLEN]				= "";
	CHAR	achRawParam[MAXSTRLEN]			= "";
	CHAR	achSystemRoot[MAXSTRLEN]		= "";
	CHAR	achConfigFilePath[MAXSTRLEN]	= "";
	CHAR	achCertFileExtension[MAXSTRLEN] = "";
	CHAR	achLogEntry[MAXSTRLEN]			= "";
	INT32	liParamLen 						= 0;
	INT32	liCertFilePathLen				= 0;
	INT32	liResult						= 0;

	DebugWrite( "[LDAPDB_Initialize] Entering LDAPDB_Initialize()." );

	/*
	    First determine the Windows System Root directory.
	    On Windows NT this was C:\winnt. On Windows XP or later
	    it could be C:\windows.
	*/

	if ( GetEnvironmentVariableA( "SystemRoot", achSystemRoot, MAXSTRLEN ) )
	{
		strlcat( achConfigFilePath, achSystemRoot, MAXSTRLEN );
		strlcat( achConfigFilePath, MODULE_CONF_FILE, MAXSTRLEN );
	}
	else goto exception;

	pfs = fopen( achConfigFilePath, "r" );             
    
	if ( !pfs )
	{
		DebugWrite( "[LDAPDB_Initialize] Error opening configuration file." );
		goto exception;
	}

    while ( ! feof(pfs) )
	{
		achLine[0] = 0; /*  For some reason, fgets() doesn't detect EOF early enough
						    and we end up looping one extra time. Clear this out first.  */

		fgets( achLine, MAXSTRLEN, pfs );

		/* Skip comment lines, NULL, or CRLF */
		if ( achLine[0] == 0 || achLine[0] == '!' || achLine[0] == '\'' || achLine[0] == '#' || achLine[0] == '\r' || achLine[0] == '\n'  ) 
		{
			continue;
		}
		
		/*  
			sscanf() will leave these variables untouched if the string
			is invalid. That will end up having us repeat some of the
			Directive cases below.
		*/
		achToken[0] = 0;
		achRawParam[0] = 0;
		achParam[0] = 0;
		/*  Assumption: Since achLine is < MAXSTRLEN, achToken & achRawParam are okay  */
		sscanf( achLine, "%s %s", achToken, achRawParam );               
		
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini line:" );
		DebugWrite( achLine );

		liParamLen = strlen( achRawParam );
		
		if ( liParamLen == 0 )
		{
			continue;
		}
		else
		{
			strlcpy( achParam, achRawParam, MAXSTRLEN );
		}

		/*
			Replace %20 with spaces.
		*/
		strlreplace( achParam, "%20", " ", MAXSTRLEN );

		/*
			Check for configuration tokens
		*/
		if ( !stricmp(achToken,"BINDUSER") )
		{
			strlcpy( gach_config_binduser, achParam, MAXSTRLEN );
			continue;
		}
		
		if ( !stricmp(achToken,"BINDPASSWORD") )
		{
			strlcpy( gach_config_bindpassword, achParam, MAXSTRLEN );
			continue;
		}
		
		if ( !stricmp(achToken,"LDAPHOST") )
		{
			strlcpy( gach_config_ldaphost, achParam, MAXSTRLEN );
			continue;
		}

		if ( !stricmp(achToken,"LDAPPORT") )
		{
			gi_config_ldapport = (INT16)atoi( achParam );
			continue;
		}

		if ( !stricmp(achToken,"LDAPFILTER") )
		{
			strlcpy( gach_config_ldapfilter, achParam, MAXSTRLEN );
			continue;
		}

		if ( !stricmp(achToken,"SEARCHBASE") )
		{
			strlcpy( gach_config_searchbase, achParam, MAXSTRLEN );
			continue;
		}
		
		if ( !stricmp(achToken,"CERTSFILE") )
		{
			liCertFilePathLen = strlen( achParam );

			/*  Strip off the file extension  */
			if ( liCertFilePathLen > 4 && liCertFilePathLen < MAXSTRLEN )
			{
				strncpy( achCertFileExtension, achParam + (liCertFilePathLen - 4), 4 );
			}

			/*  Check extension, assume b64 if DER extension not found.  */
			if ( !stricmp(achCertFileExtension, ".der") )
			{
				gli_config_certsfileformat = LDAPSSL_CERT_FILETYPE_DER;
				DebugWrite( "[LDAPDB_Initialize] DER format certificate specified." );
			}
			else
			{
				DebugWrite( "[LDAPDB_Initialize] BASE64 format certificate specified or assumed." );
			}

			strlcpy( gach_config_certsfile, achParam, MAXSTRLEN );
			continue;
		}
		
		if ( !stricmp(achToken,"NTUSER"))
		{
			strlcpy( gach_config_ntuser, achParam, MAXSTRLEN );
			continue;
		}
		
		if ( !stricmp(achToken,"NTUSERPASSWORD") )
		{
			strlcpy( gach_config_ntuserpassword, achParam, MAXSTRLEN );
			continue;
		}

		if ( !stricmp(achToken,"NTPASSWORD") )
		{
			strlcpy( gach_config_ntuserpassword, achParam, MAXSTRLEN );
			continue;
		}

#ifdef IISLDAPAUTH_CACHE
		if ( !stricmp(achToken,"CACHESIZE") )
		{
			guli_config_cachesize = atoi( achParam );
			continue;
		}

		if ( !stricmp(achToken,"CACHETIME") )
		{
			guli_config_cachetime = atoi( achParam );
			continue;
		}
#endif /* IISLDAPAUTH_CACHE */

		/*  
			Do not place any executable statements at end of loop statement.
			Gratuitous use of continue; statements above.
		*/
	}

	if ( !stricmp(gach_config_ldaphost,"") )
	{
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini: No LDAPHOST specified." );
		goto exception;
	}

	if ( !stricmp(gach_config_searchbase,"") )
	{      
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini: No SEARCHBASE specified." );
		goto exception;
	}
	
	if ( !stricmp(gach_config_ldapfilter,"") )
	{     
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini: No LDAPFILTER specified." );
		goto exception;
	}

	if ( !stricmp(gach_config_ntuser,"") )
	{  
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini: No NTUSER specified." );	
	}

	if ( !stricmp(gach_config_ntuserpassword,"") )
	{  
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini: No NTPASSWORD specified." );	
		goto exception;
	}

	/*
		Ff a user did not specify a gach_config_certsfile 
		or LDAPPORT, make sure the default port is set correctly
	*/

	if ( !stricmp(gach_config_certsfile,"") )
	{
		/*  SSL not enabled  */

		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini: No CERTSFILE specified." );	

		if ( gi_config_ldapport == 0 )
		{
			gi_config_ldapport = LDAP_PORT;
		}
	}
	else 
	{
		/*  SSL enabled  */

		if ( gi_config_ldapport == 0 )
		{
			gi_config_ldapport = LDAPS_PORT;
		}

		/*  Initialize SSL client - only do this once, not per session  */

		liResult = ldapssl_client_init( NULL, NULL );
		if ( liResult != 0 ) 
		{
			sprintf( achLogEntry, "[LDAPDB_GetUser] ldapssl_client_init() failed. Result code: %i.", liResult );
			DebugWrite( achLogEntry );
			goto exception;
		}

		gf_SSL_client_init = TRUE;

		/*	
			ldapssl_client_init() does not accept b64 certificate files.
			Since I cannot get DER format certificates to work, we now
			support b64 certificates with the following API call.
		*/
		liResult = ldapssl_add_trusted_cert( gach_config_certsfile, gli_config_certsfileformat );
		if ( liResult != 0 ) 
		{
			sprintf( achLogEntry, "[LDAPDB_GetUser] ldapssl_add_trusted_cert() failed. Result code: %i.", liResult );
			DebugWrite( achLogEntry );
			goto exception;
		}
	}

	#ifdef IISLDAPAUTH_CACHE
	if ( !Cache_Initialize(guli_config_cachesize, guli_config_cachetime) )
	{
		DebugWrite( "[LDAPDB_Initialize] Cache_Initialize() failed." );
		goto exception;
	}
	#endif /* IISLDAPAUTH_CACHE */

	bResult = TRUE;

exception:
	/*  
		If an exception occured, we jump here.
		Clean up the allocated resouces.
	*/
	if ( pfs != 0 )
	{
		fclose( pfs );  
	}

	if ( !bResult && gf_SSL_client_init )
	{
		ldapssl_client_deinit();
		gf_SSL_client_init = FALSE;
	}

	return( bResult );
}


BOOL
LDAPDB_GetUser(
    CHAR * pszLDAPUser,		/*  IN  */
    BOOL * pfFound,			/*  OUT  */
    CHAR * pszLDAPPassword,	/*  IN  */
    CHAR * pszNTUser,		/*  IN  */
    CHAR * pszNTPassword	/*  IN  */
    )
/*++

Routine Description:

    Checks the LDAP server for the username, retrieves the DN, and 
	attempts to authenticate with the LDAP server using the DN and
	the supplied password.

	If IISLDAPAUTH_CACHE is defined, a simple memory cache is queried
	before going to the network to improve performance.

Arguments:

    pszLDAPUser			- The username to find in the database (case insensitive).
						  Maximum length is SF_MAX_USERNAME bytes.
    pfFound				- Set to TRUE if the specified LDAP username was 
						  found in the database 
    pszLDAPPassword		- The external password for the found user. 
						  Maximum length is SF_MAX_PASSWORD bytes.
    pszNTUser			- The NT username associated with this user. 
						  Maximum length is SF_MAX_USERNAME bytes.
    pszNTPassword		- The password for gach_config_ntuser. 
						  Maximum length is SF_MAX_PASSWORD bytes.

Return Value:

    TRUE on success, FALSE on failure.

--*/
{
	BOOL		bResult					= FALSE;
	CHAR		achLDAPquery[MAXSTRLEN]	= "";
	CHAR		achLDAPDN[MAXSTRLEN]	= "";
	CHAR		achLogEntry[MAXSTRLEN]	= "";

	INT32		liEntries				= 0;
	INT32		liReferences			= 0;
	INT32		liResult				= 0;

	LDAP		*ld						= 0;
	LDAPMessage *res					= 0;
	LDAPMessage *msg					= 0;

    *pfFound = FALSE;
	
	/*
		Check our parameters
	*/
	if ( !(	pszLDAPUser != NULL && 
		pfFound != NULL && 
		pszLDAPPassword != NULL && 
		pszNTUser != NULL && 
		pszNTPassword != NULL) )
	{
		goto exception;
	}

	if ( strlen(pszLDAPUser) > SF_MAX_USERNAME ||
		strlen(pszLDAPPassword) > SF_MAX_PASSWORD ||
		strlen(pszNTUser) > SF_MAX_USERNAME ||
		strlen(pszNTPassword) > SF_MAX_PASSWORD )
    {
        goto exception;
    }

#ifdef IISLDAPAUTH_CACHE
	/*
		First check if the user is in the memory cache. This
		function used to be in ldapauth.c.
	*/
	if ( !Cache_GetUser(pszLDAPUser, pfFound, pszLDAPPassword, pszNTUser, pszNTPassword) )
	{
		DebugWrite( "[LDAPDB_GetUser] Cache_GetUser() failed." );
		goto exception;
	}

	if ( *pfFound )
	{
		/*
			If we found the user in the cache, set the result
			flag to TRUE and get out of here.
		*/
		DebugWrite( "[LDAPDB_GetUser] Cache_GetUser(): User found." );
		bResult = TRUE;
		goto exception;
	}
#endif /* IISLDAPAUTH_CACHE */

	/*  
		LDAP: Initialize Connection
	*/
	if ( !strcmp(gach_config_certsfile, "") )
	{
		ld = ldap_init( gach_config_ldaphost, gi_config_ldapport );
	}
	else /*  SSL configuration  */
	{
		/* Last parameter (the 1) is to specify a secure connection. */
		ld = ldapssl_init( gach_config_ldaphost, gi_config_ldapport, 1 );
	}

	if ( ld == NULL )
	{
		DebugWrite( "[LDAPDB_GetUser] ldap_init() or ldapssl_init() failed." );
		SetLastError( ERROR_BAD_USERNAME );
		goto exception;
	}
	
	/*
		LDAP: Initial Bind
		First attempt to bind using the BINDDN from config file 
		or anonymous user.
	*/
	liResult = ldap_simple_bind_s( ld, gach_config_binduser, gach_config_bindpassword );
	if ( liResult != LDAP_SUCCESS ) 
	{
		sprintf( achLogEntry, "[LDAPDB_GetUser] ldap_simple_bind_s() failed for user %s. Result code: %i.", gach_config_binduser, liResult );
		DebugWrite( achLogEntry );
		SetLastError( ERROR_BAD_USERNAME );
		goto exception;
	}

	/*
		LDAP: Query of User DN
		If the bind worked, build the query string and locate
		the user's fully qualified DN.
	*/

	strlcpy( achLDAPquery, gach_config_ldapfilter, MAXSTRLEN );
	strlreplace( achLDAPquery, USER_SEARCH_KEY, pszLDAPUser, MAXSTRLEN );

	liResult = ldap_search_s( ld, gach_config_searchbase, LDAP_SCOPE_SUBTREE, achLDAPquery, NULL, 0, &res );

	if ( liResult != LDAP_SUCCESS )
	{
		sprintf( achLogEntry, "[LDAPDB_GetUser] ldap_search_s() failed. Result code: %i.", liResult );
		DebugWrite( achLogEntry );
		DebugWrite( achLDAPquery );
		SetLastError( ERROR_BAD_USERNAME );
		goto exception;
	}
	else
	/*
		Parse the user DN query for the data.
	*/
	{
		liEntries = ldap_count_entries( ld, res );
		liReferences = ldap_count_references( ld, res );
		
		if ( liEntries > 0 ) 
		{
			if ( liEntries > 1 )
			{
				DebugWrite( "[LDAPDB_GetUser] Multiple LDAP records found. Using first one." );
			}

			msg = ldap_first_entry( ld, res );
			strlcpy( achLDAPDN, ldap_get_dn(ld,msg), MAXSTRLEN ); 

			/*
				LDAP: Final Authentication Test
				Attempt to bind (again) to the LDAP server using
				the fully qualified DN and supplied password.
			*/

			liResult = ldap_simple_bind_s( ld, achLDAPDN, pszLDAPPassword );

			if ( liResult != LDAP_SUCCESS ) 
			{
				sprintf( achLogEntry, "[LDAPDB_GetUser] LDAP DN login failed for %s. Result code: %i", pszLDAPUser, liResult );
				DebugWrite( achLogEntry );
				SetLastError( ERROR_BAD_USERNAME );
				goto exception;
			} 
			else  
			{
				*pfFound = TRUE;
				DebugWrite( "[LDAPDB_GetUser] LDAP DN Login Successful." );			
			}
		}
		else 
		{
			DebugWrite( "[LDAPDB_GetUser] LDAP DN not found." );
			SetLastError( ERROR_BAD_USERNAME );
			goto exception;
		}
	}

	if ( *pfFound )
	{
		/*  if ldapauth.ini did not specify gach_config_ntuser, use LDAP user  */

		if ( !strcmp(gach_config_ntuser, "") )
		{
			strlcpy( pszNTUser, pszLDAPUser, SF_MAX_USERNAME );
		}
		else
		{
			strlcpy( pszNTUser, gach_config_ntuser, SF_MAX_USERNAME );
		}
		
		strlcpy( pszNTPassword, gach_config_ntuserpassword, SF_MAX_PASSWORD );

		#ifdef IISLDAPAUTH_CACHE
		if ( !Cache_AddUser(pszLDAPUser, pszLDAPPassword, pszNTUser, pszNTPassword) )
		{
			DebugWrite( "[LDAPDB_GetUser] Cache_AddUser() failed." );
		}
		#endif /* IISLDAPAUTH_CACHE */
	}

	bResult = TRUE;

exception:
	/*  
		If an exception occured, we jump here.
		Clean up the allocated resouces.
	*/
	if ( ld != NULL )
	{
		ldap_unbind_s( ld );
	}

    return( bResult );
}


VOID
LDAPDB_Terminate(
    VOID
    )
/*++

Routine Description:

    Terminates the LDAP database.

Return Value:

	None.

--*/
{
	if ( gf_SSL_client_init )
	{
		ldapssl_client_deinit();
		gf_SSL_client_init = FALSE;
	}

	#ifdef IISLDAPAUTH_CACHE
	Cache_Terminate();
	#endif /* IISLDAPAUTH_CACHE */
}