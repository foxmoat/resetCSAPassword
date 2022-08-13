using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.DirectoryServices.ActiveDirectory;
using System.DirectoryServices;
using COMAdmin;
using System.Management;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace ResetCSAPassword
{
    class Program
    {

        public static readonly ILogger log = new EventLogger();
        private static int timeout = 6000;

        static void Main(string[] args)
        {
            //ILogger log = new EventLogger();
            log.Debug("ResetCSAPassword utility stated by " + Environment.UserDomainName + "\\" + Environment.UserName,true, 0);

            CheckWindowsFeature();
            string sDomain = getComputerDomain();
            string sPassword = CreatePassword(20);
            string sUsername = Regex.Replace(Regex.Replace(Environment.MachineName, @"^[a-zA-Z]+", "CSA"), @"..$", "");

            if (!UpdatePassword(sDomain, sUsername, sPassword))
            {
                Environment.Exit(2000);
            }

            if (!UpdateIIS("CICSSystemsAccess", sDomain, sUsername, sPassword))
            {
                Environment.Exit(3000);
            }

            if (!UpdateCOM(sDomain, sUsername, sPassword))
            {
                Environment.Exit(4000);
            }

            if (!UpdateCSAKeepAlive(sDomain, sUsername, sPassword))
            {
                Environment.Exit(5000);
            }
        }

        private static void CheckWindowsFeature()
        {
            bool isPresent = false;
            ManagementClass objMC = new ManagementClass("Win32_ServerFeature");
            ManagementObjectCollection objMOC = objMC.GetInstances();
            foreach (ManagementObject objMO in objMOC)
            {
                //Console.WriteLine((string)objMO.Properties["Name"].Value + ": " + objMO.Properties["ID"].Value);
                if ((string)objMO.Properties["Name"].Value == "IIS 6 Metabase Compatibility")
                {
                    isPresent = true;
                }
            }

            if (!isPresent)
            {
                log.Warn("IIS 6 Metabase Compatibility (Web-Metabase) feature is not installed. Please install this feature before running this application.",101);
                Environment.Exit(1001);
            }
        }
        public static string CreatePassword(int length)
        {
            const string valid = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789!£$%^&*()_+-=#";
            StringBuilder res = new StringBuilder();
            Random rnd = new Random();
            while (0 < length--)
            {
                res.Append(valid[rnd.Next(valid.Length)]);
            }
            return res.ToString();
        }
        private static string getComputerDomain()
        {
            try
            {
                return Domain.GetComputerDomain().Name;
            }
            catch (ActiveDirectoryObjectNotFoundException)
            {
                return "Local (No domain)";
            }
        }
        private static string ServiceErrorCodes(uint strReturnCode)
        {
            switch(strReturnCode)
            {
                case 0: return "    0 The request was accepted.";
                case 1: return "    1 The request is not supported.";
                case 2: return "    2 The user did not have the necessary access.";
                case 3: return "    3 The service cannot be stopped because other services that are running are dependent on it.";
                case 4: return "    4 The requested control code is not valid, or it is unacceptable to the service.";
                case 5: return "    5 The requested control code cannot be sent to the service because the state of the service (Win32_BaseService State property) is equal to 0, 1, or 2.";
                case 6: return "    6 The service has not been started.";
                case 7: return "    7 The service did not respond to the start request in a timely fashion.";
                case 8: return "    8 Unknown failure when starting the service." ;
                case 9: return "    9 The directory path to the service executable file was not found.";
                case 10: return "    10 The service is already running." ;
                case 11: return "    11 The database to add a new service is locked." ;
                case 12: return "    12 A dependency this service relies on has been removed from the system." ;
                case 13: return "    13 The service failed to find the service needed from a dependent service." ;
                case 14: return "    14 The service has been disabled from the system." ;
                case 15: return "    15 The service does not have the correct authentication to run on the system." ;
                case 16: return "    16 This service is being removed from the system." ;
                case 17: return "    17 The service has no execution thread.";
                case 18: return "    18 The service has circular dependencies when it starts." ;
                case 19: return "    19 A service is running under the same name." ;
                case 20: return "    20 The service name has invalid characters." ;
                case 21: return "    21 Invalid parameters have been passed to the service." ;
                case 22: return "    22 The account under which this service runs is either invalid or lacks the permissions to run the service." ;
                case 23: return "    23 The service exists in the database of services available from the system." ;
                case 24: return "    24 The service is currently paused in the system." ;
            }
            return strReturnCode + ":Error code undetermined";
        }

        static bool UpdatePassword(string domain, string username, string password)
        {
            //Obtain a reference to DirectorySearcher object and populate filter parameters
            DirectorySearcher searcher = new DirectorySearcher();
            searcher.Filter = "samaccountname=" + username;
            searcher.SearchRoot = new DirectoryEntry("LDAP://" + domain);

            //Execute command to retrieve object in AD
            SearchResult uEntries = searcher.FindOne();

            //Check to make sure object exits in domain
            if (uEntries == null)
            {
                //Console.WriteLine("Service Account (" + username + ") not found in " + domain);
                log.Error("Service Account " + username + " not found in " + domain,2001);
                return false;
            }

            try
            {
                DirectoryEntry uEntry = uEntries.GetDirectoryEntry();
                log.Debug("Service Account " + username + " found in " + domain, 2);

                //Attempt to update service account password
                //and throw an error if this fails

                uEntry.Invoke("SetPassword", new object[] { password });
                uEntry.Properties["LockOutTime"].Value = 0; //unlock account

                uEntry.Close();

                log.Debug("Password reset sucessful. Pausing for 60 seconds...", 2);
                System.Threading.Thread.Sleep(timeout);
            }
            catch (System.Reflection.TargetInvocationException e)  //user does not have enough rights to update account
            {
                log.Error("Unable to update password for " + username + ": " + e.InnerException.Message,2002);
                return false;

            }catch (Exception e){
                log.Error("Exception in UpdatePassword()", e);
                return false;
            }

            return true;
        }

        static bool UpdateIIS(string pAppPool, string pDomain, string pUsername, string pPassword)
        {
            DirectoryEntry root = null;
            DirectoryEntry AppPools = new DirectoryEntry("IIS://LocalHost/W3SVC/AppPools");

            log.Debug("Setting Application Pool to " + pAppPool,3);
            root = AppPools.Children.Find(pAppPool, "IIsApplicationPool"); 

            if (root.Name == null)
            {
                log.Error("Application Pool '" + pAppPool + "' does not exist",3001);
                return false;
            }

            try
            {
                log.Debug("Application Pool " + pAppPool + " exist.",3);

                log.Debug("Setting AppPool credentials to " + pDomain + "\\" + pUsername,3);

                root.Properties["AppPoolIdentityType"].Value = 3;
                root.Properties["WAMUserName"].Value = pDomain + @"\" + pUsername;
                root.Properties["WAMUserPass"].Value = pPassword;

                log.Debug("Commiting changes",3);
                root.Invoke("SetInfo", null);
                root.CommitChanges();
            }
            catch (Exception e)
            {
                log.Error("Exception in UpdateIIS()", e);
                return false;
            }
            return true;
        }

        static bool UpdateCOM(string domain, string username, string password)
        {
            bool appSet = false;
            COMAdminCatalog comAdmin = new COMAdminCatalog();
            COMAdminCatalogCollection comApplications = comAdmin.GetCollection("Applications");
            comApplications.Populate();

            foreach (COMAdmin.COMAdminCatalogObject comApplication in comApplications)
            {
                if (comApplication.Name == "Forwarder")
                {
                    log.Debug("Forwarder object found",4);
                    appSet = true;
                    comApplication.Value["Identity"] = domain + "\\" + username;
                    comApplication.Value["Password"] = password;
                }
            }

            if (appSet)
            {
                try
                {
                    comApplications.SaveChanges();
                    log.Debug("Credential set for Forwarder object",4);
                }
                catch
                {
                    log.Error("Unable to set password for Forwarder object",4004);
                    return false;
                }
            }
            else
            {
                log.Error("Forwarder object not found",4004);
                return false;
            }
            return true;
        }

        static bool UpdateCSAKeepAlive(string domain, string username, string password)
        {
            LsaUtility.SetRight(username, "SeServiceLogonRight");

            object result = 0;
            ObjectQuery oQuery = new ObjectQuery("select * from Win32_Service where name like 'CSAKeepAlive'"); //CSAKeepAlive

            ManagementObjectSearcher oSearcher = new ManagementObjectSearcher(oQuery);
            ManagementObjectCollection oReturnCollection = oSearcher.Get();

            foreach (ManagementObject wmiObj in oReturnCollection)
            {
                if (wmiObj.Properties["Name"].Value.ToString() == "CSAKeepAlive")
                {
                    log.Debug("Attempting to stop CSAKeepAlive service",5);
                    result = wmiObj.InvokeMethod("StopService", new object[] { null });

                    //Pause for 1 minute to wait for service to stop
                    System.Threading.Thread.Sleep(timeout);

                    if (result.ToString() != "0" && result.ToString() != "5")
                    {
                        log.Error(ServiceErrorCodes((uint)result),5001);
                        return false;
                    }

                    try
                    {
                        log.Debug("Attempting to set CSAKeepAlive service credentials",5);
                        result = wmiObj.InvokeMethod("Change", new object[] { null, null, null, null, null, null, domain + "\\" + username, password, null, null, null });
                    }
                    catch
                    {
                        log.Error("Error ocured while attempting to set CSAKeepAlive service credentials",5002);
                        return false;
                    }

                    if (result.ToString() != "0" && result.ToString() != "5")
                    {
                        log.Error(ServiceErrorCodes((uint)result),5003);
                        return false;
                    }

                    try
                    {
                        log.Debug("Attempting to start CSAKeepAlive service",5);
                        result = wmiObj.InvokeMethod("StartService", new object[] {null});
                    }
                    catch
                    {
                        log.Error("Error ocured while attempting to start CSAKeepAlive service",5004);
                        return false;
                    }

                    if (result.ToString() != "0" && result.ToString() != "5" && result.ToString() != "15")
                    {
                        log.Error(ServiceErrorCodes((uint)result),5005);
                        return false;
                    }
                    else if (result.ToString() == "15")
                    {
                        log.Warn(ServiceErrorCodes((uint)result),501);
                    }
                }
            }

            return true;
        }


    }

    public class LsaUtility
    {

        // Import the LSA functions

        [DllImport("advapi32.dll", PreserveSig = true)]
        private static extern UInt32 LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            Int32 DesiredAccess,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
        private static extern int LsaAddAccountRights(
            IntPtr PolicyHandle,
            IntPtr AccountSid,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights);

        [DllImport("advapi32")]
        public static extern void FreeSid(IntPtr pSid);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true, PreserveSig = true)]
        private static extern bool LookupAccountName(
            string lpSystemName, string lpAccountName,
            IntPtr psid,
            ref int cbsid,
            StringBuilder domainName, ref int cbdomainLength, ref int use);

        [DllImport("advapi32.dll")]
        private static extern bool IsValidSid(IntPtr pSid);

        [DllImport("advapi32.dll")]
        private static extern int LsaClose(IntPtr ObjectHandle);

        [DllImport("kernel32.dll")]
        private static extern int GetLastError();

        [DllImport("advapi32.dll")]
        private static extern int LsaNtStatusToWinError(int status);

        // define the structures

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            public int Length;
            public IntPtr RootDirectory;
            public LSA_UNICODE_STRING ObjectName;
            public UInt32 Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        // enum all policies

        private enum LSA_AccessPolicy : long
        {
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
            POLICY_NOTIFICATION = 0x00001000L
        }

        /// <summary>Adds a privilege to an account</summary>
        /// <param name="accountName">Name of an account - "domain\account" or only "account"</param>
        /// <param name="privilegeName">Name ofthe privilege</param>
        /// <returns>The windows error code returned by LsaAddAccountRights</returns>

        public static int SetRight(String accountName, String privilegeName)
        {
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

            if (!result)
            {
                winErrorCode = GetLastError();
                Program.log.Error("LookupAccountName failed with error code: " + winErrorCode, 6001);
            }
            else
            {

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

                if (winErrorCode != 0)
                {
                    Program.log.Error("OpenPolicy failed: " + winErrorCode,6002);
                }
                else
                {
                    //Now that we have the SID an the policy,
                    //we can add rights to the account.

                    //initialize an unicode-string for the privilege name
                    LSA_UNICODE_STRING[] userRights = new LSA_UNICODE_STRING[1];
                    userRights[0] = new LSA_UNICODE_STRING();
                    userRights[0].Buffer = Marshal.StringToHGlobalUni(privilegeName);
                    userRights[0].Length = (UInt16)(privilegeName.Length * UnicodeEncoding.CharSize);
                    userRights[0].MaximumLength = (UInt16)((privilegeName.Length + 1) * UnicodeEncoding.CharSize);

                    //add the right to the account
                    int res = LsaAddAccountRights(policyHandle, sid, userRights, 1);
                    winErrorCode = LsaNtStatusToWinError(res);
                    if (winErrorCode != 0)
                    {
                        Program.log.Error("LsaAddAccountRights failed: " + winErrorCode, 6003);
                    }
                    else
                    {
                        Program.log.Debug("LsaAddAccountRights successful",0);
                    }

                    LsaClose(policyHandle);
                }
                FreeSid(sid);
            }

            return winErrorCode;
        }

    }

    interface ILogger
    {
        void Debug(string text, int code);
        void Debug(string text, bool log, int code);
        void Warn(string text, int code);
        void Error(string text, int code);
        void Error(string text, Exception ex);
    }

    public class EventLogger : ILogger
    {
        public void Debug(string logMessage, int logCode)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(logMessage);
            Console.ResetColor();
        }

        public void Debug(string logMessage, bool log, int logCode = 0)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(logMessage);
            Console.ResetColor();
            if (log)
            {
                EventLog.WriteEntry(Process.GetCurrentProcess().ProcessName, logMessage, EventLogEntryType.Information, logCode);
            }
        }

        public void Warn(string logMessage, int warnCode = 100)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(logMessage);
            Console.ResetColor();
            EventLog.WriteEntry(Process.GetCurrentProcess().ProcessName, logMessage, EventLogEntryType.Warning,warnCode);
        }

        public void Error(string logMessage, int errCode = 1000)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(logMessage);
            Console.ResetColor();
            EventLog.WriteEntry(Process.GetCurrentProcess().ProcessName, logMessage, EventLogEntryType.Error, errCode);
        }

        public void Error(string logMessage, Exception ex)
        {
            Error(logMessage);
            Error(ex.StackTrace);
        }
    }
}
