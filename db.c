/*

	Released under LGPL.

	Some portions Copyright (c) 1996  Microsoft Corporation
	This program is released into the public domain for any purpose.


	Module Name:	
	
	db.c

	Abstract:

    This module implements the database routines for the authentication filter.

	Modification History:

    2002-11-24 ramr

    Changed config file parsing to support comments.

	2002-04-22 ramr

    Cleaned up LDAP code, added non-SSL support.

*/

#include <windows.h>
#include <httpfilt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "d:\isapi\ldapsdk\include\ldap.h"
#include "d:\isapi\ldapsdk\include\ldap_ssl.h"
#include "d:\isapi\ldapsdk\include\lber.h"
#include "ldapauth.h"


#define MODULE_CONF_FILE		"c:\\winnt\\ldapauth.ini"
#define DEFAULTUID				"uid"
#define MAXSTRLEN				1024


int  PORTNUMBER;
char BINDUSER[MAXSTRLEN];
char BINDPASSWORD[MAXSTRLEN];
char LDAPHOST[MAXSTRLEN];
char LDAPFILTER[MAXSTRLEN];
char LDAPUID[MAXSTRLEN];
char SEARCHBASE[MAXSTRLEN];
char CERTSFILE[MAXSTRLEN];
char NTUSER[MAXSTRLEN];
char NTUSERPASSWORD[MAXSTRLEN];


BOOL
InitializeUserDatabase(
    VOID
    )
/*++

Routine Description:

    Reads winnt\ldapauth.ini for configuration values.

Return Value:

    TRUE on success, FALSE on failure

--*/
{
    FILE *f							= 0; 
	char achLine[MAXSTRLEN]			= "";
	char achToken[MAXSTRLEN]		= "";
	char achParam[MAXSTRLEN]		= "";
	char achRawParam[MAXSTRLEN]		= "";
	int	intParamIndex				= 0;
	int intParamLen 				= 0;

	DebugWrite("[InitializeUserDatabase] Entering InitializeUserDatabase().\n");

	f = fopen( MODULE_CONF_FILE,"r" );             
    
	if ( !f )
	{
		DebugWrite("[InitializeUserDatabase] Error opening configuration file.\n");
		return FALSE;
	}

	strcpy( BINDUSER, "" );
	strcpy( BINDPASSWORD, "" );
	strcpy( LDAPHOST, "" );
	strcpy( LDAPFILTER, "" );
	strcpy( LDAPUID, "" );
	strcpy( BINDUSER, "" );
	strcpy( SEARCHBASE, "" );
	strcpy( CERTSFILE, "" );
	strcpy( NTUSER, "" );
	strcpy( NTUSERPASSWORD, "" );

    while ( ! feof(f) )
	{
		fgets( achLine, MAXSTRLEN, f );

		if ( achLine[0] == '!' ) 
		{
			//  skip comment lines
			continue;
		}
		
		sscanf( achLine,"%s %s", achToken, achRawParam );               
		
		DebugWrite( "[InitializeUserDatabase] ldapauth.ini line:" );
		DebugWrite( achLine );
		DebugWrite( "\n" );

		intParamIndex = 0;
		intParamLen = strlen( achRawParam );
		
		if ( intParamLen == 0 )
		{
			continue;
		}
		else
		{
			strcpy( achParam, achRawParam );
		}

		while (intParamIndex < intParamLen)
		{
			if ( achParam[intParamIndex]=='_' )
			{
				achParam[intParamIndex]=' ';
			}

			intParamIndex++;
		}

		if ( !strcmp(achToken,"BINDUSER") )
		{
			strcpy( BINDUSER, achParam );
		}
		
		if ( !strcmp(achToken,"BINDPASSWORD") )
		{
			strcpy( BINDPASSWORD, achParam );
		}
		
		if ( !strcmp(achToken,"LDAPHOST") )
		{
			strcpy( LDAPHOST, achParam );
		}

		if ( !strcmp(achToken,"LDAPPORT") )
		{
			PORTNUMBER = atoi( achParam );
		}

		if ( !strcmp(achToken,"LDAPFILTER") )
		{
			strcpy( LDAPFILTER, achParam );
		}

		if ( !strcmp(achToken,"LDAPUID") )
		{
			strcpy( LDAPUID, achParam );
		}

		if ( !strcmp(achToken,"SEARCHBASE") )
		{
			strcpy( SEARCHBASE, achParam );
		}
		
		if ( !strcmp(achToken,"CERTSFILE") )
		{
			strcpy( CERTSFILE, achParam );
		}
		
		if ( !strcmp(achToken,"NTUSER"))
		{
			strcpy( NTUSER, achParam );
		}
		
		if ( !strcmp(achToken,"NTUSERPASSWORD") )
		{
			strcpy( NTUSERPASSWORD, achParam );
		}
	}

	if ( !strcmp(LDAPHOST,"") )
	{
		fclose( f );        
		DebugWrite("[InitializeUserDatabase] ldapauth.ini: No LDAPHOST specified.\n");
		return FALSE;
	}

	if ( !strcmp(SEARCHBASE,"") )
	{
		fclose( f );        
		DebugWrite("[InitializeUserDatabase] ldapauth.ini: No SEARCHBASE specified.\n");
		return FALSE;
	}
	
	if ( !strcmp(LDAPFILTER,"") )
	{
		fclose( f );        
		DebugWrite("[InitializeUserDatabase] ldapauth.ini: No LDAPFILTER specified.\n");
		return FALSE;
	}

	if ( !strcmp(NTUSER,"") )
	{  
		DebugWrite("[InitializeUserDatabase] ldapauth.ini: No NTUSER specified.\n");	
	}

	//  if a user did not specify a CERTSFILE or LDAPPORT, make sure
	//  the default port is set correctly

	if ( !strcmp(CERTSFILE,"") )
	{	    
		DebugWrite("[InitializeUserDatabase] ldapauth.ini: No CERTSFILE specified.\n");	
	
		if ( PORTNUMBER == 0 )
		{
			PORTNUMBER = LDAP_PORT;
		}
	}
	else if ( PORTNUMBER == 0 )
	{
		PORTNUMBER = LDAPS_PORT;
	}

	if ( !strcmp(LDAPUID, "") )
	{
		/*  set default LDAP UID object if none specified  */
		strcpy( LDAPUID, DEFAULTUID );
	}

	fclose( f );        
	return TRUE;
}


BOOL
LookupUserInDb(
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
    pszNTUserPassword - The password for NTUser. Buffer must be at least
                  SF_MAX_PASSWORD

Return Value:

    TRUE on success, FALSE on failure

--*/
{
    CHAR		*pchEnd				= 0;
    
	DWORD		cchUser				= strlen( pszUser );
    DWORD		cch					= 0;

	LDAP		*ld					= 0;
	LDAPMessage *res				= 0;
	LDAPMessage *msg				= 0;

	int			lEntries			= 0;
	int			lReferences			= 0;
	int			lResult				= 0;

	CHAR		achLDAPquery[256]	= "";
	CHAR		achLDAPDN[256]		= "";

    *pfFound = FALSE;

	/*  If no cert file is present, use plaintext connection.  */

	if ( !strcmp(CERTSFILE, "") )
	{
		ld = ldap_init( LDAPHOST, PORTNUMBER );
	}
	else
	{
		if (ldapssl_client_init(CERTSFILE, NULL) != 0) 
		{
			DebugWrite("[LookUpUserInDB] ldapssl_client_init failed.\n");
			SetLastError( ERROR_BAD_USERNAME );
			return(FALSE);
		}

		ld = ldapssl_init( LDAPHOST, PORTNUMBER, 1 );
	}

	if ( ld==NULL )
	{
		DebugWrite("[LookUpUserInDB] ldap_init() failed.\n");
		
		SetLastError( ERROR_BAD_USERNAME );
		return( FALSE );
	}
	
	if ( ldap_simple_bind_s(ld,BINDUSER,BINDPASSWORD) == LDAP_CONNECT_ERROR ) 
	{
		DebugWrite("[LookUpUserInDB] ldap_simple_bind_s failed.\n");
		DebugWrite(BINDUSER);
		DebugWrite("\n");
		
		SetLastError( ERROR_BAD_USERNAME );
		return( FALSE );
	}

	strcpy( achLDAPquery,"(&(" );
	strcat( achLDAPquery, LDAPUID );	/* achLDAPquery= (&(uid */
	strcat( achLDAPquery, "=" );		/* achLDAPquery= (&(uid= */
	strcat( achLDAPquery,pszUser );		/* achLDAPquery= (&(uid=username */
	strcat( achLDAPquery,")" );			/* achLDAPquery= (&(uid=username) */
	strcat( achLDAPquery,LDAPFILTER );  /* achLDAPquery= (&(uid=username)LDAPFILTER */
	strcat( achLDAPquery,")" );			/* achLDAPquery= (&(uid=username)LDAPFILTER) */

	lResult = ldap_search_s( ld, SEARCHBASE, LDAP_SCOPE_SUBTREE, achLDAPquery, NULL, 0, &res );

	DebugWrite("[LookUpUserInDB] Busquem l'usuari: ");
	DebugWrite(tmp);
	DebugWrite("\n");
	DebugWrite(" Sota: ");
	DebugWrite(SEARCHBASE);
	DebugWrite("\n");

	if ( lResult == LDAP_SUCCESS ) 
	{
		lEntries = ldap_count_entries( ld, res );
		lReferences = ldap_count_references( ld, res );
		
		if ( lEntries > 0 ) 
		{
			msg = ldap_first_entry( ld,res );
			strcpy( achLDAPDN, ldap_get_dn(ld,msg) ); 

			lResult = ldap_simple_bind_s( ld, achLDAPDN, pszPassword );
			
			ldap_unbind_s( ld );
			
			if ( lResult != LDAP_SUCCESS ) 
			{
				DebugWrite("[LookUpUserInDB] No ha fet login\n");
				
				SetLastError( ERROR_BAD_USERNAME );
				return(FALSE);
			} 
			else  
			{
				*pfFound = TRUE;

				DebugWrite("[LookUpUserInDB] Si ha fet login\n");
			}
		}
		else 
		{
			ldap_unbind_s( ld );

			DebugWrite("[LookUpUserInDB] No s'ha trobat l'uid\n");
			SetLastError( ERROR_BAD_USERNAME );
			return(FALSE);
		}
	}
	else 
	{ 
		DebugWrite("[LookUpUserInDB] Usuari no trobat\n");
		ldap_unbind_s( ld );
		SetLastError( ERROR_BAD_USERNAME );

		return( FALSE );
	}

	DebugWrite("[LookUpUserInDB] Usuari autenticat\n");

	if ( *pfFound )
	{
		/*  if ldapauth.ini did not specify NTUSER, use LDAP user  */

		if ( !strcmp(NTUSER, "") )
		{
			strcpy( pszNTUser, pszUser );
		}
		else
		{
			strcpy( pszNTUser, NTUSER );
		}
		
		strcpy( pszNTUserPassword, NTUSERPASSWORD );
	}

    return TRUE;
}


VOID
TerminateUserDatabase(
    VOID
    )
/*++

Routine Description:

    Shutsdown the user database.

--*/
{
  
}



