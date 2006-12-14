/*++

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:	ldapauth.c

	Abstract:	LDAP authentication module for IIS, main routine.

  	Modification History:

	2006-12-04 ramr
	Import into SourceForge CVS. Refer to CVS log for modification history.

    2002-11-24 ramr
    Now denies blank passwords. (disable by removing the ifdef)

	2002-04-22 ramr
    Cleaned up LDAP code, added non-SSL support.

--*/

#include "ldapauth.h"


BOOL
WINAPI
DllMain(
     IN HINSTANCE hinstDll,
     IN DWORD     fdwReason,
     IN LPVOID    lpvContext OPTIONAL
     )
/*++

 Routine Description:

   This function DllLibMain() is the main initialization function for
   this DLL. It initializes local variables and prepares it to be invoked
   subsequently.

 Arguments:

   hinstDll          Instance Handle of the DLL
   fdwReason         Reason why NT called this DLL
   lpvReserved       Reserved parameter for future use.

 Return Value:

    Returns TRUE is successful; otherwise FALSE is returned.

--*/
{
	BOOL fResult = FALSE;

    switch ( fdwReason )
    {
		case DLL_PROCESS_ATTACH:

			if ( !LDAPDB_Initialize() )
			{
				DebugWrite("LDAPDEBUG: [GetFilterVersion] Database initialization failed.");
				goto exception;
			}

			/*
			    We don't care about thread attach/detach notifications
			*/
			DisableThreadLibraryCalls( hinstDll );

        break;

		case DLL_PROCESS_DETACH:
			LDAPDB_Terminate();
        break;

		default:
        break;
    }  

	fResult = TRUE;	/*  If we get here, everything was okay.  */

exception:
    return( fResult );
}  


/*++

Routine Description:

    Returns ISAPI Filter Information

Arguments:

    pVer			IIS Version Structure

Return Value:

    Returns TRUE is successful; otherwise FALSE is returned.

--*/
BOOL
WINAPI
GetFilterVersion(
	HTTP_FILTER_VERSION * pVer
    )
{
    pVer->dwFilterVersion = HTTP_FILTER_REVISION;

    /*
        Specify the types and order of notification
    */

    pVer->dwFlags = (SF_NOTIFY_SECURE_PORT        |
                     SF_NOTIFY_NONSECURE_PORT     |
                     SF_NOTIFY_AUTHENTICATION     |
                     SF_NOTIFY_LOG                |
                     SF_NOTIFY_ORDER_HIGH);

    strlcpy( pVer->lpszFilterDesc, "IIS LDAP Authentication Filter, version 2.0a1", SF_MAX_FILTER_DESC_LEN );

    return( TRUE );
}


DWORD
WINAPI
HttpFilterProc(
    HTTP_FILTER_CONTEXT *      pfc,
    DWORD                      NotificationType,
    VOID *                     pvData
    )
/*++

Routine Description:

    Filter notification entry point

Arguments:

    pfc -              Filter context
    NotificationType - Type of notification
    pvData -           Notification specific data

Return Value:

    One of the SF_STATUS response codes

--*/
{
    BOOL					fAllowed						= 0;
    CHAR					achLDAPUser[SF_MAX_USERNAME]	= "";
    CHAR					*pchLogEntry					= 0;
	HTTP_FILTER_AUTHENT		*pAuth							= 0;
    HTTP_FILTER_LOG			*pLog							= 0;
	LDAP_AUTH_CONTEXT		*pContextData					= 0; 
 	
    /*
        Handle this notification
    */

    switch ( NotificationType )
    {
		case SF_NOTIFY_AUTHENTICATION:

			pAuth = (HTTP_FILTER_AUTHENT *) pvData;

			/*
			    Ignore the anonymous user
			*/
			if ( !*pAuth->pszUser )
			{
				/*
				    Tell the server to notify any subsequent notifications in the
				    chain
				*/
				return( SF_STATUS_REQ_NEXT_NOTIFICATION );
			}

			/*
			    Save the unmapped username so we can log it later
			*/
			strlcpy( achLDAPUser, pAuth->pszUser, SF_MAX_USERNAME );

			/*
			    Make sure this user is a valid user and map to the appropriate
			    Windows NT user
			*/
			if ( !ValidateUser(pAuth->pszUser, pAuth->pszPassword, &fAllowed) )
			{
				DebugWrite( "LDAPDEBUG: [HttpFilterProc] Error validating user." );		
				SetLastError( ERROR_ACCESS_DENIED );      
				return( SF_STATUS_REQ_ERROR );
			}
			     
			if ( !fAllowed )
			{
				/*
				    This user isn't allowed access.  Indicate this to the server
				*/
				SetLastError( ERROR_ACCESS_DENIED );
				return( SF_STATUS_REQ_ERROR );
			}

			/*
			    Save the unmapped user name so we can log it later on.  We allocate
			    enough space for two usernames so we can use this memory block
			    for logging.  Note we may have already allocated it from a previous
			    request on this TCP session

			    FilterContext is used to pass information back to the IIS logging
			    subsystem. It must remain allocated and valid between notifications.
			*/

			if ( !pfc->pFilterContext )
			{
				pfc->pFilterContext = pfc->AllocMem( pfc, sizeof (LDAP_AUTH_CONTEXT), 0 );
				
				if ( !pfc->pFilterContext )
				{
					SetLastError( ERROR_NOT_ENOUGH_MEMORY );
					return( SF_STATUS_REQ_ERROR );
				}
			}
			else
			{
				ZeroMemory( pfc->pFilterContext, sizeof(LDAP_AUTH_CONTEXT) );
			}

			pContextData = pfc->pFilterContext;
			strlcpy( pContextData->szLogEntry, achLDAPUser, SF_MAX_USERNAME );
			pContextData->iLength = strlen ( achLDAPUser );

			return( SF_STATUS_REQ_HANDLED_NOTIFICATION );
	break;

    case SF_NOTIFY_LOG:

        /*
            The unmapped username is in pFilterContext if this filter
            authenticated this user. FilterContext must be allocated
		    and valid until the next notification.
        */
		if ( pfc->pFilterContext )
		{
			pContextData = pfc->pFilterContext;
		
			pLog = ( HTTP_FILTER_LOG* ) pvData;

			strcat( pContextData->szLogEntry, " (" );
			strcat( pContextData->szLogEntry, pLog->pszClientUserName );
			strcat( pContextData->szLogEntry, ")" );

			pLog->pszClientUserName = pContextData->szLogEntry;
		} 

        return( SF_STATUS_REQ_NEXT_NOTIFICATION );
	break;

    default:
        DebugWrite( "LDAPDEBUG: [HttpFilterProc] Unknown notification type." );
    break;
    }

    return( SF_STATUS_REQ_NEXT_NOTIFICATION );
}


BOOL
ValidateUser(
    IN OUT CHAR * pszUserName,
    IN OUT CHAR * pszPassword,
    OUT    BOOL * pfValid
    )
/*++

Routine Description:

    Looks up the username and confirms the user is allowed access to the
    server

Arguments:

    pszUserName - The username to validate, will contain the mapped username
                  on return.  Must be at least SF_MAX_USERNAME
    pszPassword - The password for this user.  Will contain the mapped
                  password on return.  Must be at least SF_MAX_PASSWORD
    pfValid     - Set to TRUE if the user should be logged on.

Return Value:

    TRUE on success, FALSE on failure

--*/
{
    BOOL fResult						= FALSE;
	BOOL fFound							= FALSE;
    CHAR achNTUser[SF_MAX_USERNAME]		= "";
    CHAR achNTPassword[SF_MAX_PASSWORD]	= "";
	CHAR achLogEntry[MAXSTRLEN]			= "";

    /*
        Assume we're going to fail validation
    */
    *pfValid = FALSE;

#ifdef DENYBLANKPASSWORDS
	/*  
		The Netware eDir server will incorrect allow user to authenticate
	    as anonymous if you pass a zero-length password.
	*/
	if ( !strcmp(pszPassword, "") )
	{
		sprintf( achLogEntry, "LDAPDEBUG: [ValidateUser] User %s Blank Password Denied.", pszUserName );
		DebugWrite( achLogEntry );
		goto exception;
	}
#endif

#ifdef BSTENTERPRISEHACK
    /*  Hacks for BST Enterprise  */
    if ( !stricmp(pszUserName, "bstdba") )
	{
		*pfValid = TRUE;
		fResult = TRUE;
	}
	else
	{
#endif /* BSTENTERPRISEHACK */

		if ( !LDAPDB_GetUser(pszUserName, &fFound, pszPassword, achNTUser, achNTPassword) )
		{
			DebugWrite("LDAPDEBUG: [ValidateUser] LDAPDB_GetUser() failed.");
			goto exception;
		}
		else
		{
			if ( !fFound )
			{
				DebugWrite( "LDAPDEBUG: [ValidateUser] LDAPDB_GetUser() returned no record found. User not found or LDAP authentication failed." );
			}
			else
			{
				/*
					We have a match, map to the NT user and password
				*/
				strlcpy( pszUserName, achNTUser, SF_MAX_USERNAME );
				strlcpy( pszPassword, achNTPassword, SF_MAX_PASSWORD );

				sprintf( achLogEntry, "LDAPDEBUG: [ValidateUser] User: %s Password: %s Succeeded.", pszUserName, pszPassword );
				DebugWrite( achLogEntry );

				*pfValid = TRUE;
				fResult = TRUE;
			}
		}

#ifdef BSTENTERPRISEHACK
	}
#endif /* BSTENTERPRISEHACK */

exception:
    return( fResult );
}
