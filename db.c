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

#include ".\ldapcsdk\include\ldap.h"
#include ".\ldapcsdk\include\ldap_ssl.h"
#include ".\ldapcsdk\include\lber.h"
#include "ldapauth.h"


#define MODULE_CONF_FILE		"\\ldapauth.ini"	/*  Include beginning backslash  */
#define DEFAULTUID				"uid"
#define MAXSTRLEN				1024


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
	else
	{
		return FALSE;
	}

	pfs = fopen( achConfigFilePath, "r" );             
    
	if ( !pfs )
	{
		DebugWrite("[LDAPDB_Initialize] Error opening configuration file.\n");
		return FALSE;
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
		}
		
		if ( !stricmp(achToken,"BINDPASSWORD") )
		{
			strlcpy( gach_config_bindpassword, achParam, MAXSTRLEN );
		}
		
		if ( !stricmp(achToken,"LDAPHOST") )
		{
			strlcpy( gach_config_ldaphost, achParam, MAXSTRLEN );
		}

		if ( !stricmp(achToken,"LDAPPORT") )
		{
			gi_config_ldapport = (INT16)atoi( achParam );
		}

		if ( !stricmp(achToken,"LDAPFILTER") )
		{
			strlcpy( gach_config_ldapfilter, achParam, MAXSTRLEN );
		}

		if ( !stricmp(achToken,"LDAPUID") )
		{
			strlcpy( gach_config_ldapuid, achParam, MAXSTRLEN );
		}

		if ( !stricmp(achToken,"SEARCHBASE") )
		{
			strlcpy( gach_config_searchbase, achParam, MAXSTRLEN );
		}
		
		if ( !stricmp(achToken,"CERTSFILE") )
		{
			strlcpy( gach_config_certsfile, achParam, MAXSTRLEN );
		}
		
		if ( !stricmp(achToken,"NTUSER"))
		{
			strlcpy( gach_config_ntuser, achParam, MAXSTRLEN );
		}
		
		if ( !stricmp(achToken,"NTUSERPASSWORD") )
		{
			strlcpy( gach_config_ntuserpassword, achParam, MAXSTRLEN );
		}

		if ( !stricmp(achToken,"NTPASSWORD") )
		{
			strlcpy( gach_config_ntuserpassword, achParam, MAXSTRLEN );
		}

		if ( !stricmp(achToken,"CACHESIZE") )
		{
			guli_config_cachesize = atoi( achParam );
		}

		if ( !stricmp(achToken,"CACHETIME") )
		{
			guli_config_cachetime = atoi( achParam );
		}
	}

	fclose( pfs );  

	if ( !strcmp(gach_config_ldaphost,"") )
	{
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No LDAPHOST specified.\n");
		return FALSE;
	}

	if ( !strcmp(gach_config_searchbase,"") )
	{      
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No SEARCHBASE specified.\n");
		return FALSE;
	}
	
	if ( !strcmp(gach_config_ldapfilter,"") )
	{     
		DebugWrite("[LDAPDB_Initialize] ldapauth.ini: No LDAPFILTER specified.\n");
		return FALSE;
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
		return FALSE;
	}
	#endif /* LDAP_CACHE */

	return TRUE;
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
	CHAR		achLDAPquery[MAXSTRLEN]	= "";
	CHAR		achLDAPDN[MAXSTRLEN]	= "";

	INT32		liEntries				= 0;
	INT32		liReferences			= 0;
	INT32		liResult				= 0;

	LDAP		*ld						= 0;
	LDAPMessage *res					= 0;
	LDAPMessage *msg					= 0;

    *pfFound = FALSE;

	/*  If no cert file is present, use plaintext connection.  */

	if ( !strcmp(gach_config_certsfile, "") )
	{
		ld = ldap_init( gach_config_ldaphost, gi_config_ldapport );
	}
	else
	{
		if ( ldapssl_client_init(gach_config_certsfile, NULL) != 0 ) 
		{
			DebugWrite("[LDAPDB_GetUser] ldapssl_client_init failed.\n");
			SetLastError( ERROR_BAD_USERNAME );
			return(FALSE);
		}

		ld = ldapssl_init( gach_config_ldaphost, gi_config_ldapport, 1 );
	}

	if ( ld == NULL )
	{
		DebugWrite("[LDAPDB_GetUser] ldap_init() failed.\n");
		
		SetLastError( ERROR_BAD_USERNAME );
		return( FALSE );
	}
	
	if ( ldap_simple_bind_s(ld,gach_config_binduser,gach_config_bindpassword) == LDAP_CONNECT_ERROR ) 
	{
		DebugWrite("[LDAPDB_GetUser] ldap_simple_bind_s failed.\n");
		DebugWrite(gach_config_binduser);
		DebugWrite("\n");
		
		SetLastError( ERROR_BAD_USERNAME );
		return( FALSE );
	}

	/*  FIX ME - BUFFER OVERFLOW ISSUE  */
	strlcpy( achLDAPquery, "(&(", MAXSTRLEN );
	strlcat( achLDAPquery, gach_config_ldapuid, MAXSTRLEN );	/* achLDAPquery= (&(uid */
	strlcat( achLDAPquery, "=", MAXSTRLEN );					/* achLDAPquery= (&(uid= */
	strlcat( achLDAPquery, pszUser, MAXSTRLEN );				/* achLDAPquery= (&(uid=username */
	strlcat( achLDAPquery, ")", MAXSTRLEN );					/* achLDAPquery= (&(uid=username) */
	strlcat( achLDAPquery, gach_config_ldapfilter, MAXSTRLEN ); /* achLDAPquery= (&(uid=username)gach_config_ldapfilter */
	strlcat( achLDAPquery, ")", MAXSTRLEN );					/* achLDAPquery= (&(uid=username)gach_config_ldapfilter) */

	liResult = ldap_search_s( ld, gach_config_searchbase, LDAP_SCOPE_SUBTREE, achLDAPquery, NULL, 0, &res );

	DebugWrite("[LDAPDB_GetUser] Busquem l'usuari: ");
	DebugWrite(tmp);
	DebugWrite("\n");
	DebugWrite(" Sota: ");
	DebugWrite(gach_config_searchbase);
	DebugWrite("\n");

	if ( liResult == LDAP_SUCCESS ) 
	{
		liEntries = ldap_count_entries( ld, res );
		liReferences = ldap_count_references( ld, res );
		
		if ( liEntries > 0 ) 
		{
			msg = ldap_first_entry( ld,res );
			strlcpy( achLDAPDN, ldap_get_dn(ld,msg), MAXSTRLEN ); 

			liResult = ldap_simple_bind_s( ld, achLDAPDN, pszPassword );
			
			ldap_unbind_s( ld );
			
			if ( liResult != LDAP_SUCCESS ) 
			{
				DebugWrite("[LDAPDB_GetUser] No ha fet login\n");
				
				SetLastError( ERROR_BAD_USERNAME );
				return(FALSE);
			} 
			else  
			{
				*pfFound = TRUE;

				DebugWrite("[LDAPDB_GetUser] Si ha fet login\n");
			}
		}
		else 
		{
			ldap_unbind_s( ld );

			DebugWrite("[LDAPDB_GetUser] No s'ha trobat l'uid\n");
			SetLastError( ERROR_BAD_USERNAME );
			return(FALSE);
		}
	}
	else 
	{ 
		DebugWrite("[LDAPDB_GetUser] Usuari no trobat\n");
		ldap_unbind_s( ld );
		SetLastError( ERROR_BAD_USERNAME );

		return( FALSE );
	}

	DebugWrite("[LDAPDB_GetUser] Usuari autenticat\n");

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
	}

    return TRUE;
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



