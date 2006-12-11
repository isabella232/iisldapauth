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

#include ".\novell-cldap\Win32\inc\ldap.h"
#include ".\novell-cldap\Win32\inc\ldap_ssl.h"
#include ".\novell-cldap\Win32\inc\lber.h"
#include "ldapauth.h"

/*
	Global Configuration Variables
	These are read from the ldapauth.ini file.
*/

INT16	gi_config_ldapport						= 0;
CHAR	gach_config_binduser[MAXSTRLEN]			= "";
CHAR	gach_config_bindpassword[MAXSTRLEN]		= "";
CHAR	gach_config_ldaphost[MAXSTRLEN]			= "";
CHAR	gach_config_ldapfilter[MAXSTRLEN]		= "";
CHAR	gach_config_ldapuid[MAXSTRLEN]			= "";
CHAR	gach_config_searchbase[MAXSTRLEN]		= "";
CHAR	gach_config_certsfile[MAXSTRLEN]		= "";
CHAR	gach_config_ntuser[MAXSTRLEN]			= "";
CHAR	gach_config_ntuserpassword[MAXSTRLEN]	= "";
#ifdef LDAP_CACHE
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

    TRUE on success, FALSE on failure

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
	INT32	liParamIndex					= 0;
	INT32	liParamLen 						= 0;

	DebugWrite("[LDAPDB_Initialize] Entering LDAPDB_Initialize().\n");

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
		DebugWrite("[LDAPDB_Initialize] Error opening configuration file.\n");
		goto exception;
	}

    while ( ! feof(pfs) )
	{
		fgets( achLine, MAXSTRLEN, pfs );

		/* Skip comment lines */
		if ( achLine[0] == '!' || achLine[0] == '\'' || achLine[0] == '#' ) 
		{
			continue;
		}
		
		/*  Assumption: Since achLine is < MAX_STRING_LEN, achToken & achRawParam are okay  */
		sscanf( achLine, "%s %s", achToken, achRawParam );               
		
		DebugWrite( "[LDAPDB_Initialize] ldapauth.ini line:" );
		DebugWrite( achLine );
		DebugWrite( "\n" );

		liParamIndex = 0;
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
			Substitute underscores for spaces
		*/

		while ( liParamIndex < liParamLen )
		{
			if ( achParam[liParamIndex]=='_' )
			{
				achParam[liParamIndex]=' ';
			}

			liParamIndex++;
		}

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

		if ( !stricmp(achToken,"LDAPUID") )
		{
			strlcpy( gach_config_ldapuid, achParam, MAXSTRLEN );
			continue;
		}

		if ( !stricmp(achToken,"SEARCHBASE") )
		{
			strlcpy( gach_config_searchbase, achParam, MAXSTRLEN );
			continue;
		}
		
		if ( !stricmp(achToken,"CERTSFILE") )
		{
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

#ifdef LDAP_CACHE
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
#endif /* LDAP_CACHE */
		/*  
			Do not place any executable statements at end of loop statement.
			Gratuitous use of continue; statements above.
		*/
	}

	if ( !strcmp(gach_config_ldaphost,"") )
	{
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No LDAPHOST specified.\n");
		goto exception;
	}

	if ( !strcmp(gach_config_searchbase,"") )
	{      
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No SEARCHBASE specified.\n");
		goto exception;
	}
	
	if ( !strcmp(gach_config_ldapfilter,"") )
	{     
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No LDAPFILTER specified.\n");
		goto exception;
	}

	if ( !strcmp(gach_config_ntuser,"") )
	{  
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No NTUSER specified.\n");	
	}

	//  if a user did not specify a gach_config_certsfile or LDAPPORT, make sure
	//  the default port is set correctly

	if ( !strcmp(gach_config_certsfile,"") )
	{	    
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No CERTSFILE specified.\n");	
	
		if ( gi_config_ldapport == 0 )
		{
			gi_config_ldapport = LDAP_PORT;
		}
	}
	else if ( gi_config_ldapport == 0 )
	{
		gi_config_ldapport = LDAPS_PORT;
	}

	if ( !strcmp(gach_config_ldapuid, "") )
	{
		/*  set default LDAP UID object if none specified  */
		strlcpy( gach_config_ldapuid, DEFAULTUID, MAXSTRLEN );
	}

	#ifdef LDAP_CACHE
	if ( !Cache_Initialize(guli_config_cachesize, guli_config_cachetime) )
	{
		DebugWrite("[LDAPDB_Initialize] Cache initialization failed.\n");
		goto exception;
	}
	#endif /* LDAP_CACHE */

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

	return( bResult );
}


BOOL
LDAPDB_GetUser(
    IN CHAR * pszUser,
    OUT BOOL * pfFound,
    IN CHAR * pszPassword,
    OUT CHAR * pszNTUser,
    OUT CHAR * pszNTUserPassword
    )
/*++

Routine Description:

    Looks up the username in the database and returns the other attributes
    associated with this user

    The file data is not sorted to simulate the cost of an external database
    lookup.

Arguments:

    pszUserName - The username to find in the database (case insensitive)
    pfFound     - Set to TRUE if the specified user name was found in the
                  database
    pszPassword - The external password for the found user.  Buffer must be
                  at least SF_MAX_PASSWORD bytes.
    pszNTUser   - The NT username associated with this user, Buffer must be at
                  least SF_MAX_USERNAME bytes
    pszNTUserPassword - The password for gach_config_ntuser. Buffer must be at least
                  SF_MAX_PASSWORD

Return Value:

    TRUE on success, FALSE on failure

--*/
{
	BOOL		bResult					= FALSE;
	CHAR		achLDAPquery[MAXSTRLEN]	= "";
	CHAR		achLDAPDN[MAXSTRLEN]	= "";

	INT32		liEntries				= 0;
	INT32		liReferences			= 0;
	INT32		liResult				= 0;

	LDAP		*ld						= 0;
	LDAPMessage *res					= 0;
	LDAPMessage *msg					= 0;

    *pfFound = FALSE;

#ifdef LDAP_CACHE
	/*
		First check if the user is in the memory cache. This
		function used to be in ldapauth.c.
	*/
	if ( !Cache_GetUser(pszUser, pfFound, pszPassword, pszNTUser, pszNTUserPassword) )
	{
		DebugWrite( "[ValidateUser] LookupUserInCache() failed.\n" );
		goto exception;
	}

	if ( *pfFound )
	{
		/*
			If we found the user in the cache, set the result
			flag to TRUE and get out of here.
		*/
		bResult = TRUE;
		goto exception;
	}
#endif /* LDAP_CACHE */

	/*  
		LDAP: Initialize Connection
	*/
	if ( !strcmp(gach_config_certsfile, "") )
	{
		ld = ldap_init( gach_config_ldaphost, gi_config_ldapport );
	}
	else
	{
		if ( ldapssl_client_init(gach_config_certsfile, NULL) != 0 ) 
		{
			DebugWrite( "[LDAPDB_GetUser] ldapssl_client_init failed.\n" );
			SetLastError( ERROR_BAD_USERNAME );
			goto exception;
		}

		ld = ldapssl_init( gach_config_ldaphost, gi_config_ldapport, 1 );
	}

	if ( ld == NULL )
	{
		DebugWrite("[LDAPDB_GetUser] ldap_init() failed.\n");
		SetLastError( ERROR_BAD_USERNAME );
		goto exception;
	}
	
	/*
		LDAP: Initial Bind
		First attempt to bind using the binddn or anonymous.
	*/
	liResult = ldap_simple_bind_s( ld, gach_config_binduser, gach_config_bindpassword );
	if ( liResult != LDAP_SUCCESS ) 
	{
		DebugWrite("[LDAPDB_GetUser] ldap_simple_bind_s failed.\n");
		DebugWrite(gach_config_binduser);
		DebugWrite("\n");
		
		SetLastError( ERROR_BAD_USERNAME );
		goto exception;
	}

	/*
		LDAP: Query of User DN
		If the bind worked, build the query string and locate
		the user's fully qualified DN.
	*/
	strlcpy( achLDAPquery, "(&(", MAXSTRLEN );					/* achLDAPquery= (&( */
	strlcat( achLDAPquery, gach_config_ldapuid, MAXSTRLEN );	/* achLDAPquery= (&(uid */
	strlcat( achLDAPquery, "=", MAXSTRLEN );					/* achLDAPquery= (&(uid= */
	strlcat( achLDAPquery, pszUser, MAXSTRLEN );				/* achLDAPquery= (&(uid=username */
	strlcat( achLDAPquery, ")", MAXSTRLEN );					/* achLDAPquery= (&(uid=username) */
	strlcat( achLDAPquery, gach_config_ldapfilter, MAXSTRLEN ); /* achLDAPquery= (&(uid=username)gach_config_ldapfilter */
	strlcat( achLDAPquery, ")", MAXSTRLEN );					/* achLDAPquery= (&(uid=username)gach_config_ldapfilter) */

	liResult = ldap_search_s( ld, gach_config_searchbase, LDAP_SCOPE_SUBTREE, achLDAPquery, NULL, 0, &res );

	if ( liResult != LDAP_SUCCESS )
	{
		DebugWrite("[LDAPDB_GetUser] ldap_search_s failed.\n");
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
			msg = ldap_first_entry( ld,res );
			strlcpy( achLDAPDN, ldap_get_dn(ld,msg), MAXSTRLEN ); 

			/*
				LDAP: Final Authentication Test
				Attempt to bind (again) to the LDAP server using
				the fully qualified DN and supplied password.
			*/

			liResult = ldap_simple_bind_s( ld, achLDAPDN, pszPassword );

			if ( liResult != LDAP_SUCCESS ) 
			{
				DebugWrite("[LDAPDB_GetUser] No ha fet login\n");
				SetLastError( ERROR_BAD_USERNAME );
				goto exception;
			} 
			else  
			{
				*pfFound = TRUE;
				DebugWrite("[LDAPDB_GetUser] Supplied login failed to bind.\n");			
			}
		}
		else 
		{
			DebugWrite("[LDAPDB_GetUser] No s'ha trobat l'uid\n");
			SetLastError( ERROR_BAD_USERNAME );
			goto exception;
		}
	}

	DebugWrite("[LDAPDB_GetUser] NT User Authentication\n");

	if ( *pfFound )
	{
		/*  if ldapauth.ini did not specify gach_config_ntuser, use LDAP user  */

		if ( !strcmp(gach_config_ntuser, "") )
		{
			strlcpy( pszNTUser, pszUser, SF_MAX_USERNAME );
		}
		else
		{
			strlcpy( pszNTUser, gach_config_ntuser, SF_MAX_USERNAME );
		}
		
		strlcpy( pszNTUserPassword, gach_config_ntuserpassword, SF_MAX_PASSWORD );

		#ifdef LDAP_CACHE
		Cache_AddUser( pszUser, pszPassword, pszNTUser, pszNTUserPassword );
		#endif /* LDAP_CACHE */
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

--*/
{
  
}



