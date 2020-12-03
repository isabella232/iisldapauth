# IIS LDAP Auth ISAPI Module Fork 

imported from https://sourceforge.net/projects/iisldapauth/

# IIS LDAP Authentication Filter

Version  2.0 (Pre-release Build 3) Release Notes
Updated: 12/25/2006
Author:  Ram Rajadhyaksha
---------------------------------------------------------------

# IMPORTANT NOTES

This pre-release software has not been tested completely. Do 
not use this software in production environments.

If you are upgrading from Version 1.x, the format of the
configuration file "ldapauth.ini" has changed significantly.
Specifically, the LDAPFILTER directive now requires a full
LDAP syntax query.

Please read the documentation completely before installing
the software. This software requires the Novell C LDAP SDK. 
The Novell package can be downloaded at:

http://developer.novell.com/wiki/index.php/LDAP_Libraries_for_C


---------------------------------------------------------------
# CHANGE LOG

## December 25, 2006:

SSL support now reads both DER and base-64 format certificates.

Fixed problem with duplicate thread calls to 
ldapssl_client_init().

Logging support is included in the debug DLL only. It has been
tested in IIS6 with success. If you want to use the debug
version for logging, make sure an empty text file 
"ldapauth.log" is created on the system drive (e.g. C:\). The 
log file must have permissions so the web server process can 
write entries. The simplest way to do this is to allow the 
"Everyone" group read/write privileges. Do not do this for 
production environments!

The LOGFILE directive is no longer valid. Please remove it from
your configuration file.


## December 19, 2006: 

Released with working SSL support. SSL requires a base-64 
format certificate. Read Section 3 of the documentation.


## December 17, 2006:

First public v2.0 build.


---------------------------------------------------------------
# FOR PRODUCT FEEDBACK

Please submit feed back at SourceForge project page:
http://www.sourceforge.org/products/iisldapauth/

This product is developed by Inflection Technology, LLC,
http://www.inflectiontech.com.


---------------------------------------------------------------
# SUPPORT

Product support is available on a subscription basis. Please
contact:

Inflection Technology, LLC.
100 E. Campus View Blvd, Suite 250
Columbus, Ohio 43235
Telephone: 614 438 2609
http://www.inflectiontech.com


---------------------------------------------------------------
Copyright (c) 2006, Inflection Technology, LLC
