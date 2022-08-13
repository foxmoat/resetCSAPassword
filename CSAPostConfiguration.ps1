<#
.SYNOPSIS
This powershell script configures the CSAServer branch application

.DESCRIPTION
The script is to be used in the ServerBuild (SB) framework to configure CSAServer post installation. 

.PARAMETER Domain
Domain of service account

.PARAMETER ServiceAccount
Service account to use for COM+ and CSAKeepAlive Service

.PARAMETER ServiceAccountPass
Password for the service account

.EXAMPLE
Configure CSA

CSAPostConfiguration.ps1 -Domain "fm.foxmoat.net" -ServiceAccount "Sven" -ServiceAccountPass "Ingvars"

.NOTES
Modification History:
V1.0.0	18/07/16 - Initial Joshua Amira
#>
Param
(
	[Parameter(Position=0, Mandatory=$false, ValueFromPipeline=$false)]
	[string] $ServiceAccount = ($env:COMPUTERNAME -replace '^[a-z]',"CSA" -replace '.$' -replace '.$').toUpper(),
	[Parameter(Position=1, Mandatory=$true, ValueFromPipeline=$false)]
	[string] $ServiceAccountPass,
    [Parameter(Position=2, Mandatory=$false, ValueFromPipeline=$false)]
    [string]$Domain = $([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name) 
) 
set-psdebug -strict
$errorActionPreference = 'SilentlyContinue'


# --------------------------------------------------------------------------------------------------
# Constant Variables
# --------------------------------------------------------------------------------------------------

set-variable -name INT_RC_SUCCESS 			-value 0 -option constant
set-variable -name INT_RC_FAILURE 			-value 1 -option constant
set-variable -name INT_MIN_PS_VERSION 		-value 20 -option constant
set-variable -name STR_LOGFILE_PATH_PREFIX	-value "C:\foxmoat\Logs\" -option constant
set-variable -name STR_LOGFILE_EXTENSION 	-value ".log" -option constant
set-variable -name INT_LOG_ERROR 			-value 1 -option constant
set-variable -name INT_LOG_INFORMATION 		-value 0 -option constant
set-variable -name INT_OUTPUT_TO_CONSOLE 	-value 1 -option constant
set-variable -name STR_PRODUCTNAME			-value "Configure CSA COM+ Object" -option constant
set-variable -name STR_PRODUCTVERSION	 	-value "1.1.0" -option constant

# --------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------
# Functions
# --------------------------------------------------------------------------------------------------
# --------------------------------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 
#   Func:	QuitScript
# 
#   Input:	Return code to exit with
#  
#   Purpose: Clean up open objects and exit with return code
# 		
# ---------------------------------------------------------------------------
Function QuitScript([int]$intRC) {
	#Release object resources
	# $objSQ.Dispose()
	Write-Output "`nExit code: $intRC"
	exit $intRC
}

# ---------------------------------------------------------------------------
# 
#   Func:	ServiceErrorCodes
# 
#   Input:	Service exit code description
#  
#   Purpose: Readable description of service call results
# 		
# ---------------------------------------------------------------------------
function ServiceErrorCodes ($strReturnCode)
{
#This function will print the right value. The error code list was extracted using the MSDN documentation for the change method as December 2014
Switch ($strReturnCode) 
    {
    0{ Return  "    0 The request was accepted."} 
    1{ Return  "    1 The request is not supported."} 
    2{ Return  "    2 The user did not have the necessary access."} 
    3{ Return  "    3 The service cannot be stopped because other services that are running are dependent on it."} 
    4{ Return  "    4 The requested control code is not valid, or it is unacceptable to the service."} 
    5{ Return  "    5 The requested control code cannot be sent to the service because the state of the service (Win32_BaseService State property) is equal to 0, 1, or 2."} 
    6{ Return  "    6 The service has not been started."} 
    7{ Return  "    7 The service did not respond to the start request in a timely fashion."} 
    8{ Return  "    8 Unknown failure when starting the service." } 
    9{ Return  "    9 The directory path to the service executable file was not found."} 
    10{ Return  "    10 The service is already running." } 
    11{ Return  "    11 The database to add a new service is locked." } 
    12{ Return  "    12 A dependency this service relies on has been removed from the system." } 
    13{ Return  "    13 The service failed to find the service needed from a dependent service." } 
    14{ Return  "    14 The service has been disabled from the system." } 
    15{ Return  "    15 The service does not have the correct authentication to run on the system." } 
    16{ Return  "    16 This service is being removed from the system." }
    17{ Return  "    17 The service has no execution thread."} 
    18{ Return  "    18 The service has circular dependencies when it starts." } 
    19{ Return  "    19 A service is running under the same name." } 
    20{ Return  "    20 The service name has invalid characters." } 
    21{ Return  "    21 Invalid parameters have been passed to the service." } 
    22{ Return  "    22 The account under which this service runs is either invalid or lacks the permissions to run the service." } 
    23{ Return  "    23 The service exists in the database of services available from the system." } 
    24{ Return  "    24 The service is currently paused in the system." } 
    }
}


# ---------------------------------------------------------------------------
# 
#   Func:	WriteToLogAndConsole
# 
#   Input:	Full path to logfile, string to write, whether error or information, whether to write to console
# 
#   Purpose: Write String to specified Logfile and write to console if required
# 		
# ---------------------------------------------------------------------------
Function WriteToLogAndConsole([string]$TextToWrite, [int]$intMessType = $INT_LOG_INFORMATION, [int]$intWriteToConsole = $INT_OUTPUT_TO_CONSOLE) {

	# Write output to console if specified
	If ($intWriteToConsole -eq $INT_OUTPUT_TO_CONSOLE) {
		Write-Host $TextToWrite
	}

	$Error.Clear()
	(Get-Date).ToString()+" $TextToWrite" | Out-File -FilePath $strScriptLog -Append 
	if (($? -eq $false) -and ($intMessType -eq $INT_LOG_INFORMATION)) {
		Write-Host "ERROR: Failed to write to text file $strLogfile. $($Error[0])"
		QuitScript $INT_RC_FAILURE
	}
}

# ---------------------------------------------------------------------------
# 
#   Sub:	ReportAndErrorHandling
# 
#   Input:	
# 
#   Purpose: 
# 			
# 		
# ---------------------------------------------------------------------------
Function ReportAndErrorHandling {
	param(
		[int] $intReturnCode, 
		[int[]] $intAcceptableReturnCodes = (0), 
		[string] $strDescription
	)
	
	if($intAcceptableReturnCodes -contains $intReturnCode) {
		#OK - contine execution
		$strDescription = "SUCCESS: " + $strDescription
		$strDescription += "`n`tRETURN CODE: $intReturnCode"

		WriteToLogAndConsole $strDescription $INT_LOG_INFORMATION $INT_OUTPUT_TO_CONSOLE
		
		
	} else {
		#Fail 
		$strDescription = "FAIL: " + $strDescription
		$strDescription += "`n`tRETURN CODE: $intReturnCode"

		WriteToLogAndConsole $strDescription $INT_LOG_ERROR $INT_OUTPUT_TO_CONSOLE
		QuitScript $intReturnCode
	} 
}

# ---------------------------------------------------------------------------
# 
# Func:	CheckPSVersion
# 
# Input: Minimum version of Powershell supported by this script
# 
# Purpose: Check to determine if the Powershell environment is capabale of running this script
# 		
# ---------------------------------------------------------------------------
Function CheckPSVersion([int]$IntMinPSVer) {
  $IntVerMajor = [int]
	$IntVerMinor = [int]
	$IntVersion = [int]
	$StrFuncNamePrefix = "Func CheckPSVersion:"
	
	WriteToLogAndConsole "$strScriptLog" "$StrFuncNamePrefix Checking Powershell Version ..." $INT_LOG_INFORMATION ""
	
	$Error.Clear()
	$IntVerMajor = (get-host).version.major
	
	ErrorHandling $INT_RC_FAILURE $? "$StrFuncNamePrefix Failed to determine ScriptEngineMajorVersion. " "$strScriptLog"
	WriteToLogAndConsole "$strScriptLog" "$StrFuncNamePrefix Engine Major Version is $IntVerMajor" $INT_LOG_INFORMATION ""
	
	$IntVerMinor = (get-host).version.minor
	ErrorHandling $INT_RC_FAILURE $? "$StrFuncNamePrefix Failed to determine ScriptEngineMinorVersion. " "$strScriptLog"
	WriteToLogAndConsole "$strScriptLog" "$StrFuncNamePrefix Engine Minor Version is $IntVerMinor" $INT_LOG_INFORMATION ""
	
	$IntVersion = (($IntVerMajor*10) + $IntVerMinor)
	If ($IntVersion -lt $IntMinPSVer) { 
    	ErrorHandling $INT_RC_FAILURE $INT_RC_FAILURE "$StrFuncNamePrefix Powershell Version found $IntVersion is less than minimum expected: $IntMinPSVer" "$strScriptLog"
	}
	WriteToLogAndConsole "$strScriptLog" "$StrFuncNamePrefix Powershell Version found $IntVersion is greater than or equal to minimum required $IntMinPSVer" $INT_LOG_INFORMATION ""
}

# ###########################################################################
# 
# Func: 	SetForwarderOptions
# Input:    Update COM+ Component Properties
# Purpose:  1. Set the Identity of the Forwarder COM+ object to the Service Account
#           2. Add the Service Account as a user in the Role sub component
# 		
# ############################################################################
Function SetForwarderOptions([string]$username, [string]$password, [string]$domain)
{
    try
    {
        # Create a new COM+ object
        $comAdmin = New-Object -COMObject COMAdmin.COMAdminCatalog
        WriteToLogAndConsole "COM+ object created successfully"
        [bool]$appSet = $false

        # Get a reference to all sub-components
        $Applications = $comAdmin.GetCollection("Applications") 
        $Applications.Populate()
        WriteToLogAndConsole "Reference obtained for the COM+ collection"

        # Get a referemce to the Forwarder COM+ object
        foreach ($Application in $Applications)
        {
            if ($Application.Name -eq "Forwarder")
            {
                $appSet = $true
                # Change the Identity property to the username in format DOMAIN\username
                $Application.Value("Identity") = "$domain\$username"
                WriteToLogAndConsole "Set COM+ Identity to $domain\$username"

                # Set the password of the Identity property
                $Application.Value("Password") = "$password"
                WriteToLogAndConsole "Set COM+ Identity password"
            
                # Get a reference to the Roles sub-component of the Fowarder COM+ object
                $Roles = $Applications.GetCollection("Roles",$Application.key)
                $Roles.Populate()
                WriteToLogAndConsole "Reference obtained for the Roles sub-component of the Fowarder COM+ object"

                # Get a reference to the Users collection of the CSAServices property
                # Can also be called using ("UsersInRole",$Services.Key)
                $Usrs = $Roles.GetCollection("UsersInRole","CSAServices")
                $Usrs.Populate()
                WriteToLogAndConsole "Reference obtained for the Users collection of the CSAServices Roles property"

                # Get a reference to a new user to be added and set the value to the service account
                $Usr = $Usrs.Add()
                $Usr.Value("User") = "$domain\$username"
                WriteToLogAndConsole "Add user to $domain\$username to the Users collection of the Roles sub-component"

                # Save all changes to the Role's UsersInRole property
                $Usrs.SaveChanges()|Out-Null
                WriteToLogAndConsole "Save all changes to the Users collection"
            }
        }

        if (!$appSet)
        {
            # Forwarder COM+ object not present. Check that component is properly installed
            ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	        -strDescription	"Forwarder COM+ object not present. Check that component is properly installed"
        }

        # Save all changes to the Forwarder COM+ component. 
        $Applications.SaveChanges()|Out-Null
        WriteToLogAndConsole "Save all changes to the Forwarder COM+ object"
    }
    catch [Exception]
    {
        ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	    -strDescription	"$($_.Exception.Message)"
    }
}


# ###########################################################################
# 
# Func:    SetCSAKeepAliveIdentity
# Input:   Update CSAKeepAlive Credentials 
# Purpose: 1. Stop the service
#          2. Set the identity of the CSAKeepAlive service
#          3. Start the Service 		
# ############################################################################
Function SetCSAKeepAlive ([string]$username, [string]$password, [string]$domain)
{
    try
    {
        # Check to see if CSAKeepAliveIdentity exists and return a reference if it does.
        $srvc = gwmi win32_service -filter "name like 'CSAKeepAlive'"
        if ($srvc)
        {
            # Stop the service and return a reference of the command result
            $Value = $srvc.StopService()
            if ($value.ReturnValue -ne "0" -and $value.ReturnValue -ne "5")
            {
                ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	            -strDescription	"$(ServiceErrorCodes $Value.ReturnValue)"
            }
            WriteToLogAndConsole "Service stopped with returncode $(ServiceErrorCodes $Value.ReturnValue)"

            # Set the DOMAIN\username, password values.
            $Value = $srvc.change($null,$null,$null,$null,$null,$null,"$domain\$username",$password,$null,$null,$null) 
            if ($value.ReturnValue -ne "0" -and $value.ReturnValue -ne "5")
            {
                ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	            -strDescription	"$(ServiceErrorCodes $Value.ReturnValue)"
            }
            WriteToLogAndConsole "Service credentials updated with returncode $(ServiceErrorCodes $Value.ReturnValue)"

            # Strat the service
            $Value = $srvc.StartService()
            if ($value.ReturnValue -ne "0" -and $value.ReturnValue -ne "5" -and $value.ReturnValue -ne "15")
            {
                ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	            -strDescription	"$(ServiceErrorCodes $Value.ReturnValue)"
            }elseif ($value.ReturnValue -eq "15")
            {
                WriteToLogAndConsole "Service could not be started. Returncode $(ServiceErrorCodes $Value.ReturnValue)"
            }
            WriteToLogAndConsole "Service configuration completed with returncode $(ServiceErrorCodes $Value.ReturnValue)"
        }
        else
        {
            # Service is not installed.
            ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	        -strDescription	"CSAKeepAliveIdentity service is not installed."
        }
    }
    catch [Exception]
    {
        ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	    -strDescription	"$($_.Exception.Message)"
    }
}

# ###########################################################################
# 
# Func:    getPlums
# Input:   Get and verify Credentials 
# Purpose: 1. Validate Credential location
#          2. Validate Credential Value
#          3. Return Credential value
# ############################################################################
function getPlums()
{
    if (!(Test-Path "C:\foxmoat\Packages\secure.bin"))
    {
        WriteToLogAndConsole -strDescription "Password has not been updated. Using default password..." $INT_LOG_INFORMATION $INT_OUTPUT_TO_CONSOLE
        Return 0
    }

    try{
        $secureString = Get-Content C:\foxmoat\Packages\secure.bin|ConvertTo-SecureString
        $cred = New-Object System.Management.Automation.PSCredential -ArgumentList $ServiceAccount,$secureString

        Get-ADDomain -Server $Domain -Credential $cred|Out-Null
        
        Return [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureString))
    
    }
    catch [System.Security.Authentication.AuthenticationException]
    {
        ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	    -strDescription	"Password not valid: $($_.Exception.Message)"
        
    }
    catch
    {
        ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	    -strDescription	"$($_.Exception.Message)"
    }

    
}


function Set-Privileges ([string]$username, [string]$domain, [string]$Privilege)
{
# C# code from http://www.codeproject.com/Articles/4863/LSA-Functions-Privileges-and-Impersonation
    $Source = @"
    using System;
    using System.Text;
    using System.Runtime.InteropServices;

    namespace Privileges {
        public class LsaUtility {

            // Import the LSA functions

            [DllImport("advapi32.dll", PreserveSig=true)]
            private static extern UInt32 LsaOpenPolicy(
                ref LSA_UNICODE_STRING SystemName,
                ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
                Int32 DesiredAccess,
                out IntPtr PolicyHandle
            );

            [DllImport("advapi32.dll", SetLastError=true, PreserveSig=true)]
            private static extern int LsaAddAccountRights(
                IntPtr PolicyHandle,
                IntPtr AccountSid,
                LSA_UNICODE_STRING[] UserRights,
                int CountOfRights);

            [DllImport("advapi32")]
            public static extern void FreeSid(IntPtr pSid);

            [DllImport( "advapi32.dll", CharSet=CharSet.Auto, SetLastError=true, PreserveSig=true)]
            private static extern bool LookupAccountName(
                string lpSystemName, string lpAccountName,
                IntPtr psid,
                ref int cbsid,
                StringBuilder domainName, ref int cbdomainLength, ref int use );

            [DllImport( "advapi32.dll")]
            private static extern bool IsValidSid(IntPtr pSid);

            [DllImport("advapi32.dll")]
            private static extern int LsaClose(IntPtr ObjectHandle);

            [DllImport("kernel32.dll")]
            private static extern int GetLastError();

            [DllImport("advapi32.dll")]
            private static extern int LsaNtStatusToWinError(int status);

            // define the structures

            [StructLayout(LayoutKind.Sequential)]
            private struct LSA_UNICODE_STRING {
                public UInt16 Length;
                public UInt16 MaximumLength;
                public IntPtr Buffer;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct LSA_OBJECT_ATTRIBUTES{
                public int Length;
                public IntPtr RootDirectory;
                public LSA_UNICODE_STRING ObjectName;
                public UInt32 Attributes;
                public IntPtr SecurityDescriptor;
                public IntPtr SecurityQualityOfService;}

            // enum all policies

            private enum LSA_AccessPolicy : long{
                POLICY_VIEW_LOCAL_INFORMATION = 0x00000001L,
                POLICY_VIEW_AUDIT_INFORMATION = 0x00000002L,
                POLICY_GET_PRIVATE_INFORMATION = 0x00000004L,
                POLICY_TRUST_ADMIN = 0x00000008L,
                POLICY_CREATE_ACCOUNT = 0x00000010L,
                POLICY_CREATE_SECRET = 0x00000020L,
                POLICY_CREATE_PRIVILEGE = 0x00000040L,
                POLICY_SET_DEFAULT_QUOTA_LIMITS = 0x00000080L,
                POLICY_SET_AUDIT_REQUIREMENTS = 0x00000100L,
                POLICY_AUDIT_LOG_ADMIN = 0x00000200L,
                POLICY_SERVER_ADMIN = 0x00000400L,
                POLICY_LOOKUP_NAMES = 0x00000800L,
                POLICY_NOTIFICATION  = 0x00001000L
            }

            /// <summary>Adds a privilege to an account</summary>
            /// <param name="accountName">Name of an account - "domain\account" or only "account"</param>
            /// <param name="privilegeName">Name ofthe privilege</param>
            /// <returns>The windows error code returned by LsaAddAccountRights</returns>
            public static int SetRight(String accountName, String privilegeName){
                int winErrorCode = 0; //contains the last error

                //pointer an size for the SID
                IntPtr sid = IntPtr.Zero;
                int sidSize = 0;
                //StringBuilder and size for the domain name
                StringBuilder domainName = new StringBuilder();
                int nameSize = 0;
                //account-type variable for lookup
                int accountType = 0;

                //get required buffer size
                LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

                //allocate buffers
                domainName = new StringBuilder(nameSize);
                sid = Marshal.AllocHGlobal(sidSize);

                //lookup the SID for the account
                bool result = LookupAccountName(String.Empty, accountName, sid, ref sidSize, domainName, ref nameSize, ref accountType);

                //say what you're doing for debug
                //Console.WriteLine("LookupAccountName result = "+result);
                //Console.WriteLine("IsValidSid: "+IsValidSid(sid));
                //Console.WriteLine("LookupAccountName domainName: "+domainName.ToString());

                if( ! result ){
                    winErrorCode = GetLastError();
                    Console.WriteLine("LookupAccountName failed: "+ winErrorCode);
                }else{

                    //initialize an empty unicode-string
                    LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
                    //combine all policies
                    int access = (int)(
                        LSA_AccessPolicy.POLICY_AUDIT_LOG_ADMIN |
                        LSA_AccessPolicy.POLICY_CREATE_ACCOUNT |
                        LSA_AccessPolicy.POLICY_CREATE_PRIVILEGE |
                        LSA_AccessPolicy.POLICY_CREATE_SECRET |
                        LSA_AccessPolicy.POLICY_GET_PRIVATE_INFORMATION |
                        LSA_AccessPolicy.POLICY_LOOKUP_NAMES |
                        LSA_AccessPolicy.POLICY_NOTIFICATION | 
                        LSA_AccessPolicy.POLICY_SERVER_ADMIN |
                        LSA_AccessPolicy.POLICY_SET_AUDIT_REQUIREMENTS |
                        LSA_AccessPolicy.POLICY_SET_DEFAULT_QUOTA_LIMITS |
                        LSA_AccessPolicy.POLICY_TRUST_ADMIN |
                        LSA_AccessPolicy.POLICY_VIEW_AUDIT_INFORMATION |
                        LSA_AccessPolicy.POLICY_VIEW_LOCAL_INFORMATION
                        );
                    //initialize a pointer for the policy handle
                    IntPtr policyHandle = IntPtr.Zero;

                    //these attributes are not used, but LsaOpenPolicy wants them to exists
                    LSA_OBJECT_ATTRIBUTES ObjectAttributes = new LSA_OBJECT_ATTRIBUTES();
                    ObjectAttributes.Length = 0;
                    ObjectAttributes.RootDirectory = IntPtr.Zero;
                    ObjectAttributes.Attributes = 0;
                    ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
                    ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;            

                    //get a policy handle
                    int resultPolicy = (int)LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);
                    winErrorCode = LsaNtStatusToWinError(resultPolicy);

                    if(winErrorCode != 0){
                        Console.WriteLine("OpenPolicy failed: "+ winErrorCode);
                    }else{
                        //Now that we have the SID an the policy,
                        //we can add rights to the account.

                        //initialize an unicode-string for the privilege name
                        LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
                        userRights[0] = new LSA_UNICODE_STRING();
                        userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
                        userRights[0].Length = (UInt16)( privilegeName.Length * UnicodeEncoding.CharSize );
                        userRights[0].MaximumLength = (UInt16)( (privilegeName.Length+1) * UnicodeEncoding.CharSize );

                        //add the right to the account
                        int res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
                        winErrorCode = LsaNtStatusToWinError(res);
                        if(winErrorCode != 0){
                            Console.WriteLine("LsaAddAccountRights failed: "+ winErrorCode);
                        }else{
                            Console.WriteLine("LsaAddAccountRights successful");
                        }

                        LsaClose(policyHandle);
                    }
                    FreeSid(sid);
                }

                return winErrorCode;
            }

        }
    }
"@ 

    Add-Type -TypeDefinition $Source -Language CSharp  

    [Privileges.LsaUtility]::SetRight("$domain\$username", $Privilege) | Out-Null
}

$strThisScript = Split-Path $MyInvocation.MyCommand.Definition -leaf -resolve
$strScriptLog = $STR_LOGFILE_PATH_PREFIX + $strThisScript + $STR_LOGFILE_EXTENSION

WriteToLogAndConsole "######################################################################" $INT_LOG_INFORMATION ""
WriteToLogAndConsole "Starting execution ...." $INT_LOG_INFORMATION $INT_OUTPUT_TO_CONSOLE
WriteToLogAndConsole "######################################################################" $INT_LOG_INFORMATION ""

CheckPSVersion $INT_MIN_PS_VERSION

WriteToLogAndConsole "Debug information will be stored in $strScriptLog" $INT_LOG_INFORMATION $INT_OUTPUT_TO_CONSOLE

if (!($ServiceAccount -and $ServiceAccountPass)) {
	ReportAndErrorHandling -intReturnCode $INT_RC_FAILURE `
	-strDescription	"Username or Password was not specified."
}

$searcher = [adsisearcher]"objectcategory=user"
$searcher.filter = "samaccountname=$ServiceAccount"

if ($searcher.FindOne())
{
    WriteToLogAndConsole "Service account ($Domain\$ServiceAccount) exists in domain. Attempting to retrieve the updated password ..." `
    $INT_LOG_INFORMATION $INT_OUTPUT_TO_CONSOLE
    if (getPlums)
    {
        WriteToLogAndConsole "Using updated password ..." $INT_LOG_INFORMATION $INT_OUTPUT_TO_CONSOLE
        $ServiceAccountPass = getPlums
    }    
}
else
{
    WriteToLogAndConsole "Service account ($Domain\$ServiceAccount) does not exist in domain. Using the default credentials..."
    $ServiceAccount = "Service-BranchServic"      # SamAccountName delibrately truncated due to restrictions in AD
    $ServiceAccountPass = "Ph0n3r1ngs!"
}

#*==================================================
#* SCRIPT BODY
#*==================================================
WriteToLogAndConsole "Setting Forwarder COM+ object Identity and Role settings"
SetForwarderOptions -username $ServiceAccount -password $ServiceAccountPass -domain $Domain

WriteToLogAndConsole "Setting CSAKeepAlive service credentials"
Set-Privileges -username $ServiceAccount -Privilege "SeServiceLogonRight" -domain $Domain
SetCSAKeepAlive -username $ServiceAccount -password $ServiceAccountPass -domain $Domain

QuitScript $INT_RC_SUCCESS
#*==================================================
#* END OF SCRIPT: [BranchIIS85Role]
#*==================================================