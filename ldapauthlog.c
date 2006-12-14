/*++

	IIS LDAP Authentication Module
	Copyright 2006 Inflection Technology, LLC
	For more information, visit http://www.inflectiontech.com.

	Released under LGPL terms.

	Some portions Copyright Salvador Salanova Fortmann.
	Some portions Copyright Microsoft Corporation.

	File Name:	ldapauthlog.c

	Abstract:
	This module implements a file logging system.

  	Modification History:

	2006-12-12 ramr
	File created.

--*/

#include "ldapauthlog.h"

/*
	Global Configuration Variables
*/
FILE				*gpfsLogFile	= 0;
CRITICAL_SECTION	gsLogLock		= {0};

BOOL
Log_Initialize(
    const CHAR * pszLogPath
    )
/*++

 Routine Description:

   Initializes the logging system. When called, a header will
   be written to the log. 

 Arguments:

   pszLogPath		Windows pathname to the log file

 Return Value:

    Returns TRUE is successful; otherwise FALSE is returned.

--*/
{
	BOOL	fResult = FALSE;

	if ( gpfsLogFile == NULL ) goto exception;

	InitializeCriticalSection( &gsLogLock );
	EnterCriticalSection( &gsLogLock );

	if ( pszLogPath != NULL )
	{
		gpfsLogFile = fopen( pszLogPath, "a" );

		if ( gpfsLogFile != NULL )
		{
			fprintf( gpfsLogFile, "%s", "\n----------------------------" ); 
			fprintf( gpfsLogFile, "%s", "\nIIS LDAP Auth: Module Loaded" ); 
			fflush( gpfsLogFile );
			fResult = TRUE;
		}
	}

	LeaveCriticalSection( &gsLogLock );

exception:
	return ( fResult );
}


BOOL
Log_Write(
    CHAR * pszLogLine,
	UINT16 liLevel
    )
/*++

 Routine Description:

   Writes a line to the log file.

 Arguments:

   pszLogLine		C string to write to the log file

 Return Value:

    Returns TRUE is successful; otherwise FALSE is returned.

--*/
{
	BOOL	fResult = FALSE;

	if ( gpfsLogFile != NULL && pszLogLine != NULL )
	{
		fprintf( gpfsLogFile, "\n%s", pszLogLine ); 
		fResult = TRUE;
	}

	return ( fResult );
}


BOOL
Log_Flush(
    VOID
    )
/*++

 Routine Description:

	Flushes data in the log line.

 Arguments:

	None

 Return Value:

    Returns TRUE is successful; otherwise FALSE is returned.

--*/
{
	BOOL	fResult = FALSE;

	if ( gpfsLogFile != NULL )
	{
		fflush( gpfsLogFile ); 
		fResult = TRUE;
	}
	return ( fResult );
}


VOID
Log_Terminate(
    VOID
    )
/*++

 Routine Description:

   Terminates the logging system. Closes the logging file. 

 Arguments:

	None

 Return Value:

    None

--*/
{
	if ( gpfsLogFile != NULL )
	{
		EnterCriticalSection( &gsLogLock );
		fclose( gpfsLogFile );
		gpfsLogFile = 0;
		LeaveCriticalSection( &gsLogLock );
		DeleteCriticalSection( &gsLogLock );
	}
}