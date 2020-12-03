# LDAP Auth ISAPI Module 

Updated Notes, 11/24/2002 - Ram Rajadhyaksha

IMPORTANT NOTES AND CHANGES

1. This IIS module requires the Sun iPlanet (Netscape) LDAP SDK. You can
   download the SDK from:

   http://softeval.sun.com/NASApp/iplanetdownload/Download?release_id=5176-21

2. SSL support does not work. The LDAP library returns an error whenever
   we attempt to bind using SSL. If anyone can figure out what the deal is,
   I would appreciate it.
   
3. The configuration file syntax has changed from version 1.0. Please make
   sure you update your ldapauth.ini file if you are upgrading.
   
4. This version includes a hack for BST Consultants BST Enterprise product.
   The username "bstdba" will never use LDAP, but instead defer to the
   Windows NT security. You will need to disable the #ifdef if you do not
   want this functionality.
   
5. LDAPPORT is a new option in the configuration file. If you do not
   specify this parameter AND omit the CERTSFILE parameter, the
   default port will be 389. If you omit the LDAPPORT parameter
   and include a CERTSFILE value, the default port will be 636.
   
   Since SSL support doesn't work, you should not include a CERTSFILE
   parameter at this time.
   
   
# INSTALLATION INSTRUCTIONS

1. Copy iPlanet SDK DLLs to C:\WINNT\SYSTEM32. At a minimum, you will 
   need to copy the following files:
   
   libnspr4.dll
   libplc4.dll
   libplds4.dll
   nsldap32v50.dll
   nsldappr32v50.dll
   nsldapssl32v50.dll
   nss3.dll
   ssl3.dll

   You can also keep the libraries in a different directory, however 
   you will have to add that directory to the system $PATH variable.
      
2. Install C:\WINNT\LDAPAUTH.INI. A sample file has been included. The
   syntax is as follows:
   
   KEY<space>VALUE
   
   Spaces in a value must be replaced by "_" characters.
   
   Here are the different options:
   
   Key                Value
   -------------------------------------------------------------------------------
   LDAPHOST           IP address of LDAP server. (required)
   LDAPPORT           Port number of LDAP service. (optional)
   LDAPFILTER         LDAP filter to restrict search to user objects. (optional)
   BINDUSER           User to do the initial LDAP bind. (optional)
   BINDPASSWORD       Bind password. (optional)
   SEARCHBASE         Initial search base. (required)
   NTUSER             NT user to authenticate to IIS. (optional)
   NTUSERPASSWORD     NT password authenticate to IIS. (required)
   LDAPUID            The UID type, if not specified defaults to "uid". (optional)
   CERTSFILE          SSL certificate path. (optional)
   
   The parsing of the configuration file is extremely simple and will
   break if you do anything complicated. 
   
   The NTUSER/NTUSERPASSWORD are used to authenticate to IIS after the 
   LDAP user and password have been verified. Either you can specify
   one NTUSER or you can simple leave NTUSER blank and the LDAP CN
   will be used instead. In either case, a valid NTUSERPASSWORD is required.

3. Copy ldapauth.dll to any location. Go into the Internet Administrator
   and add the ISAPI application.
   
4. Enable BASIC authentication, disable Anonymous and NTLM. Unfortunately
   NTLM authentication is not supported via the IIS API.

5. Test and pray it works. Good luck.


# TROUBLESHOOTING

It is very likely something will not work the first time you install the
module. Make sure you check the following:

1. The NT user IIS is using for authentication must be allowed the
   "login locally" privilege. One way to eliminate this issue is to make
   the user part of the administrators group. (DO NOT do this in a production
   environment, but only for the purpose of troubleshooting.)
   
   See <http://support.microsoft.com/default.aspx?scid=KB;EN-US;q142868&> 
   for more information.
   
2. Test your LDAP server. Use the ldapsearch.exe program bundled with the
   iPlanet LDAP SDK. If the ldapsearch fails to run, then you have a problem
   with the SDK installation. Make sure all the DLLs have been copied to
   the WINNT\SYSTEM32 directory.
   
   An example of a test would be:
   
   ldapsearch -h 192.168.1.1 -b "o=myorg" "uid=ramr"
   
3. Test the NT account- are the password and group privileges correct? IIS 
   does not recognize privilege modifications to user accounts until you 
   restart the process.

4. LDAP users with blank passwords are not allowed. This is due to some
   LDAP servers authenticating users anonymously if they supplied a blank
   password.
   
   
# BUILD INSTRUCTIONS

1. Get a copy of Visual C++ 6.0. You will need Service Pack 5.

2. Get a copy of the iPlanet LDAP SDK. Version 5.0 is current as of 4/27/2002.

3. Open the project, fix the include file paths in db.c. Make sure the
   compiler can find the LDAP SDK libraries.
   
4. Build.


# DEBUG INSTRUCTIONS

Debugging the ISAPI library is a bit tricky. You must first attach to the
IIS server, start the WWW handler, and then set your break points. The
VC++ debugger will not allow you to set break points until this is done
properly.

I have not had any success in setting break points in the DllMain() entry
function. If you figure out how to break there, please let me know. 

IMPORTANT NOTE: You must be using VC++ 6.0 SP5 or the ATTACH TO PROCESS 
function will not work with system processes.

1. Start IIS Administrator

2. Do "net stop w3svc" to stop the WWW server.

3. Install the ISAPI DLL.

4. Choose BUILD > START DEBUG > ATTACH TO PROCESS in VC++ 6.0, pick
   the "inetinfo" system process.

5. Start the web server - "net start w3svc".

6. Set your break points.


# Future Enhancements
-------------------------------------------------------------------------------
1. Multiple LDAP servers for fail-over.
2. Make the memory cache not suck.

The module has been tested with the Novell eDirectory 8.5 LDAP server.

Ram Rajadhyaksha
Inflection Technology, LLC
www.inflectiontech.com
ramr@inflectiontech.com





# IISLdapAuth ISAPI filter

This is the distribution of an ISAPI filter which authenticates users 
against an ldap server.

It is based on the AuthFilt example to be found in the MS's Option Pack. 
As a reference, a copy is included: iisfilter.zip.

As client libraries Netscape's ldap sdk 4.11 is used, because of ssl.
Redistributable dlls and libs can be found under ldap2 directory.
The whole sdk can be found in http://developer.netscape.com

The ISAPI filter and its source code can be found under ldapfilter.X.Y.Z

Installation instructions and other docs are to be found in each ldapfilter
directory.

Licensing issues and other legalese is pending, but intention is put it
under GPL.

There is no warranty at all.
Use at your own risk.
It is being developed for my own needs. 
If it works for you, great! If not, great too!


Salvador Salanova Fortmann

-------------------------------------------------------------------------------
