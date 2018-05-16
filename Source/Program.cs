//"Secure" AutoLogon developed by Roger Zander
//Some Sources & Ideas found on:
//- LSA Functions - Privileges and Impersonation:  http://www.codeproject.com/csharp/lsadotnet.asp
//- http://www.pinvoke.net/

using System;
using System.Collections.Generic;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;
using System.Collections;

[assembly: CLSCompliant(true)]

internal static class SafeNativeMethods
{
    #region Structures
    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING : IDisposable
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
        public void Dispose()
        {
            this = new LSA_UNICODE_STRING();
        }
    }

    public struct LSA_OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public LSA_UNICODE_STRING ObjectName;
        public UInt32 Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    public enum LSA_AccessPolicy : long
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
    #endregion

    #region DLL Imports
    [DllImport("advapi32")]
    public static extern IntPtr FreeSid(IntPtr pSid);

    [DllImport("advapi32.dll", PreserveSig = true)]
    public static extern UInt32 LsaOpenPolicy(
        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        Int32 DesiredAccess,
        out IntPtr PolicyHandle);

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaStorePrivateData(
        IntPtr PolicyHandle,
        LSA_UNICODE_STRING[] KeyName,
        LSA_UNICODE_STRING[] PrivateData);

    [DllImport("advapi32.dll", PreserveSig = true)]
    public static extern uint LsaRetrievePrivateData(
        IntPtr PolicyHandle,
        LSA_UNICODE_STRING[] KeyName,
        out IntPtr PrivateData);

    [DllImport("advapi32.dll", PreserveSig = true)]
    public static extern uint LsaNtStatusToWinError(uint status);

    [DllImport("advapi32.dll")]
    public static extern uint LsaClose(IntPtr ObjectHandle);
    #endregion
}

namespace AutoLogon
{
    class Program
    {
        #region Functions

        /// <summary>
        /// Store Encrypted Data
        /// </summary>
        /// <param name="keyName"></param>
        /// <param name="Data"></param>
        /// <returns></returns>
        public static long StoreData(String keyName, String Data)
        {
            long winErrorCode = 0; 
            IntPtr sid = IntPtr.Zero;
            int sidSize = 0;

            //allocate buffers
            sid = Marshal.AllocHGlobal(sidSize);

            //initialize an empty unicode-string
            SafeNativeMethods.LSA_UNICODE_STRING systemName = new SafeNativeMethods.LSA_UNICODE_STRING();
            
            //Set desired access rights (requested rights)
            int access = (int)(SafeNativeMethods.LSA_AccessPolicy.POLICY_CREATE_SECRET); 
            //initialize a pointer for the policy handle
            IntPtr policyHandle = IntPtr.Zero;

            //these attributes are not used, but LsaOpenPolicy wants them to exists
            SafeNativeMethods.LSA_OBJECT_ATTRIBUTES ObjectAttributes = new SafeNativeMethods.LSA_OBJECT_ATTRIBUTES();
            ObjectAttributes.Length = 0;
            ObjectAttributes.RootDirectory = IntPtr.Zero;
            ObjectAttributes.Attributes = 0;
            ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            //get a policy handle
            uint resultPolicy = SafeNativeMethods.LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);

            winErrorCode = SafeNativeMethods.LsaNtStatusToWinError(resultPolicy);

            if (winErrorCode != 0)
            {
                Console.WriteLine("OpenPolicy failed: " + winErrorCode);
            }
            else
            {
                //initialize an unicode-string for the keyName
                SafeNativeMethods.LSA_UNICODE_STRING[] uKeyName = new SafeNativeMethods.LSA_UNICODE_STRING[1];
                uKeyName[0] = new SafeNativeMethods.LSA_UNICODE_STRING();
                uKeyName[0].Buffer = Marshal.StringToHGlobalUni(keyName);
                uKeyName[0].Length = (UInt16)(keyName.Length * UnicodeEncoding.CharSize);
                uKeyName[0].MaximumLength = (UInt16)((keyName.Length + 1) * UnicodeEncoding.CharSize);

                //initialize an unicode-string for the Data to encrypt
                SafeNativeMethods.LSA_UNICODE_STRING[] uData = new SafeNativeMethods.LSA_UNICODE_STRING[1];
                uData[0] = new SafeNativeMethods.LSA_UNICODE_STRING();
                uData[0].Buffer = Marshal.StringToHGlobalUni(Data);
                uData[0].Length = (UInt16)(Data.Length * UnicodeEncoding.CharSize);
                uData[0].MaximumLength = (UInt16)((Data.Length + 1) * UnicodeEncoding.CharSize);

                //Store Encrypted Data:
                SafeNativeMethods.LsaStorePrivateData(policyHandle, uKeyName, uData);

                //winErrorCode = LsaNtStatusToWinError(res);
                if (winErrorCode != 0)
                {
                    Console.WriteLine("LsaStorePrivateData failed: " + winErrorCode);
                }

                SafeNativeMethods.LsaClose(policyHandle);
            }
            SafeNativeMethods.FreeSid(sid);
            return winErrorCode;
        }

        /// <summary>
        /// Retrieve Encrypted Data
        /// </summary>
        /// <param name="keyName"></param>
        /// <returns></returns>
        public static string RetrieveData(String keyName)
        {
            string sout = "";
            long winErrorCode = 0;
            IntPtr sid = IntPtr.Zero;
            int sidSize = 0;

            //allocate buffers
            sid = Marshal.AllocHGlobal(sidSize);

            //initialize an empty unicode-string
            SafeNativeMethods.LSA_UNICODE_STRING systemName = new SafeNativeMethods.LSA_UNICODE_STRING();

            //Set desired access rights (requested rights)
            int access = (int)(SafeNativeMethods.LSA_AccessPolicy.POLICY_CREATE_SECRET);
            //initialize a pointer for the policy handle
            IntPtr policyHandle = IntPtr.Zero;

            //these attributes are not used, but LsaOpenPolicy wants them to exists
            SafeNativeMethods.LSA_OBJECT_ATTRIBUTES ObjectAttributes = new SafeNativeMethods.LSA_OBJECT_ATTRIBUTES();
            ObjectAttributes.Length = 0;
            ObjectAttributes.RootDirectory = IntPtr.Zero;
            ObjectAttributes.Attributes = 0;
            ObjectAttributes.SecurityDescriptor = IntPtr.Zero;
            ObjectAttributes.SecurityQualityOfService = IntPtr.Zero;

            //get a policy handle
            uint resultPolicy = SafeNativeMethods.LsaOpenPolicy(ref systemName, ref ObjectAttributes, access, out policyHandle);

            winErrorCode = SafeNativeMethods.LsaNtStatusToWinError(resultPolicy);

            if (winErrorCode != 0)
            {
                Console.WriteLine("OpenPolicy failed: " + winErrorCode);
            }
            else
            {
                //initialize an unicode-string for the keyName
                SafeNativeMethods.LSA_UNICODE_STRING[] uKeyName = new SafeNativeMethods.LSA_UNICODE_STRING[1];
                uKeyName[0] = new SafeNativeMethods.LSA_UNICODE_STRING();
                uKeyName[0].Buffer = Marshal.StringToHGlobalUni(keyName);
                uKeyName[0].Length = (UInt16)(keyName.Length * UnicodeEncoding.CharSize);
                uKeyName[0].MaximumLength = (UInt16)((keyName.Length + 1) * UnicodeEncoding.CharSize);

                //Store Encrypted Data:
                IntPtr pData;
                long result = SafeNativeMethods.LsaRetrievePrivateData(policyHandle, uKeyName, out pData);

                //winErrorCode = LsaNtStatusToWinError(res);
                if (winErrorCode != 0)
                {
                    Console.WriteLine("LsaStorePrivateData failed: " + winErrorCode);
                }
                SafeNativeMethods.LSA_UNICODE_STRING ss = (SafeNativeMethods.LSA_UNICODE_STRING)Marshal.PtrToStructure(pData, typeof(SafeNativeMethods.LSA_UNICODE_STRING));
                sout = Marshal.PtrToStringAuto(ss.Buffer);

                SafeNativeMethods.LsaClose(policyHandle);
            }
            SafeNativeMethods.FreeSid(sid);


            return sout;
        }

        #endregion
        
        static void Main(string[] args)
        {
            ArrayList aArgs = new ArrayList();
            foreach(string s in args)
            {
                aArgs.Add(s.ToUpper(System.Globalization.CultureInfo.InvariantCulture));
            }

            if (aArgs.Contains("/GET"))
            {
                try
                {
                    System.Console.WriteLine("Password: " + RetrieveData("DefaultPassword"));
                }
                catch(Exception ex)
                {
                    System.Console.WriteLine("Error: " + ex.Message);
                }
            }

            //Disable Autologon
            if (aArgs.Contains("/DEL"))
            {
                try
                {
                    RegistryKey OurKey = Registry.LocalMachine;
                    OurKey = OurKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", true);
                    OurKey.SetValue("DefaultUserName", "");
                    OurKey.DeleteValue("AutoAdminLogon",false);
                    OurKey.DeleteValue("AutoLogonCount",false);
                    OurKey.DeleteValue("ForceAutoLogon",false);
                    OurKey.DeleteValue("DisableCAD",false);
                    OurKey.DeleteValue("DefaultPassword",false);
                    StoreData("DefaultPassword", "");
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine("Error: " + ex.Message);
                }
            }

            if (aArgs.Count >= 2)
            {
                try
                {
                    RegistryKey OurKey = Registry.LocalMachine;
                    OurKey = OurKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", true);

                    //Check if Domain exists
                    if (args[0].Contains(@"\"))
                    {
                        OurKey.SetValue("DefaultUserName", args[0].Split('\\')[1]);
                        OurKey.SetValue("DefaultDomainName", System.Environment.ExpandEnvironmentVariables(args[0].Split('\\')[0]));
                    }
                    else
                    {
                        OurKey.SetValue("DefaultUserName", args[0]);
                        //Use Computername as Domain-name
                        OurKey.SetValue("DefaultDomainName", System.Environment.MachineName);
                    }


                    OurKey.SetValue("AutoAdminLogon", "1");
                    OurKey.DeleteValue("DefaultPassword", false);

                    //Set Autologon Count
                    int iCount;
                    if (aArgs.Count > 2)
                    {
                        if (int.TryParse(args[2], out iCount))
                        {
                            if (iCount > 0)
                            {
                                OurKey.SetValue("AutoLogonCount", iCount);
                            }
                            else
                            {
                                OurKey.DeleteValue("AutoLogonCount", false);
                            }
                        }
                    }
                    else
                    {
                        OurKey.DeleteValue("AutoLogonCount", false);
                    }

                    //Additional Options
                    if (aArgs.Contains("/DISABLECAD"))
                    {
                        OurKey.SetValue("DisableCAD", "1");
                    }
                    if (aArgs.Contains("/FORCEAUTOLOGON"))
                    {
                        OurKey.SetValue("ForceAutoLogon", "1");
                    }

                    StoreData("DefaultPassword", args[1]);

                    System.Console.WriteLine(@"Autologon activated...");
                }
                catch (Exception ex)
                {
                    System.Console.WriteLine("Error: " + ex.Message);
                }

            }

            if((aArgs.Count == 0) | aArgs.Contains("/?"))
            {
                System.Console.WriteLine(@"Autologon.exe <Domain\Username> <Password> [LogonCount] [/DisableCAD] [/ForceAutoLogon]");
                System.Console.WriteLine(@"Autologon.exe /GET");
                System.Console.WriteLine(@"Autologon.exe /DEL");
            }
        }
    }
}
