<#
    .Synopsis
        Provides access to Windows Credential Manager basic functionality for client scripts. Allows the user
        to add, delete, and show credentials within the Windows Credential Manager.

        Refactored From: https://gallery.technet.microsoft.com/scriptcenter/PowerShell-Credentials-d44c3cde

        ****************** IMPORTANT ******************
        *
        * If you use this script from the PS console, you 
        * should ALWAYS pass the Target, User and Password
        * parameters using single quotes:
        * 
        *  .\CredMan.ps1 -AddCred -Target 'http://server' -User 'JoeSchmuckatelli' -Pass 'P@55w0rd!'
        * 
        * to prevent PS misinterpreting special characters 
        * you might use as PS reserved characters
        * 
        ****************** IMPORTANT ******************

    .Description
        See .SYNOPSIS

    .NOTES
        Original Author: Jim Harrison (jim@isatools.org)
        Date  : 2012/05/20
        Vers  : 1.5

    .PARAMETER AddCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it in conjunction with -Target, -User, and -Pass
        parameters to add a new credential or update existing credentials.

    .PARAMETER Comment
        This parameter is OPTIONAL.

        This parameter takes a string that represents additional information that you wish
        to place in the credentials comment field. Use with the -AddCred switch.

    .PARAMETER CredPersist
        This parameter is OPTIONAL, however, it has a default value of "ENTERPRISE".

        This parameter takes a string. Valid values are:
        "SESSION", "LOCAL_MACHINE", "ENTERPRISE"
        
        ENTERPRISE persistance means that the credentials will survive logoff and reboot.
        
    .PARAMETER CredType
        This parameter is OPTIONAL, however, it has a default value of "GENERIC".

        This parameter takes a string. Valid values are:
        "GENERIC", "DOMAIN_PASSWORD", "DOMAIN_CERTIFICATE",
        "DOMAIN_VISIBLE_PASSWORD", "GENERIC_CERTIFICATE", "DOMAIN_EXTENDED",
        "MAXIMUM", "MAXIMUM_EX"
        
        ****************** IMPORTANT ******************
        *
        * I STRONGLY recommend that you become familiar 
        * with http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        * before you create new credentials with -CredType other than "GENERIC"
        * 
        ****************** IMPORTANT ******************

    .PARAMETER DelCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to remove existing credentials. If more than one
        credential sets have the same -Target, you must use this switch in conjunction with the
        -CredType parameter.

    .PARAMETER GetCred
        This parameter is OPTIONAL.

        This parameter is a switch. Use it to retrieve an existing credential. The
        -CredType parameter may be required to access the correct credential if more set
        of credentials have the same -Target.

    .PARAMETER Pass
        This parameter is OPTIONAL, however, it is MANDATORY if the -AddCred switch is used.

        This parameter takes a string that represents tha secret/password that you would like to store.

    .PARAMETER RunTests
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will run built-in Win32 CredMan
        functionality tests.

    .PARAMETER ShoCred
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the function will retrieve all credentials stored for
        the interactive user.

    .PARAMETER Target
        This parameter is OPTIONAL, however, it is MANDATORY unless the -ShoCred switch is used.

        This parameter takes a string that specifies the authentication target for the specified credentials
        If not specified, the value provided to the -User parameter is used.

    .PARAMETER User
        This parameter is OPTIONAL.

        This parameter takes a string that represents the credential's UserName.
        

    .LINK
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://stackoverflow.com/questions/7162604/get-cached-credentials-in-powershell-from-windows-7-credential-manager
        http://msdn.microsoft.com/en-us/library/windows/desktop/aa374788(v=vs.85).aspx
        http://blogs.msdn.com/b/peerchan/archive/2005/11/01/487834.aspx

    .EXAMPLE
        # Stores the credential for 'UserName' with a password of 'P@55w0rd!' for authentication against 'http://aserver' and adds a comment of 'cuziwanna'
        Manage-StoredCredentials -AddCred -Target 'http://aserver' -User 'UserName' -Password 'P@55w0rd!' -Comment 'cuziwanna'

    .EXAMPLE
        # Removes the credential used for the target 'http://aserver' as credentials type 'DOMAIN_PASSWORD'
        Manage-StoredCredentials -DelCred -Target 'http://aserver' -CredType 'DOMAIN_PASSWORD'

    .EXAMPLE
        # Retreives the credential used for the target 'http://aserver'
        Manage-StoredCredentials -GetCred -Target 'http://aserver'

    .EXAMPLE
        # Retrieves a summary list of all credentials stored for the interactive user
        Manage-StoredCredentials -ShoCred

    .EXAMPLE
        # Retrieves a detailed list of all credentials stored for the interactive user
        Manage-StoredCredentials -ShoCred -All

#>
function Manage-StoredCredentials {
    [CmdletBinding()]
    Param (
     [Parameter(Mandatory=$false)]
        [Switch] $AddCred,

     [Parameter(Mandatory=$false)]
        [Switch]$DelCred,
     
        [Parameter(Mandatory=$false)]
        [Switch]$GetCred,
     
        [Parameter(Mandatory=$false)]
        [Switch]$ShoCred,

     [Parameter(Mandatory=$false)]
        [Switch]$RunTests,
     
        [Parameter(Mandatory=$false)]
        [ValidateLength(1,32767) <# CRED_MAX_GENERIC_TARGET_NAME_LENGTH #>]
        [String]$Target,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,512) <# CRED_MAX_USERNAME_LENGTH #>]
        [String]$User,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,512) <# CRED_MAX_CREDENTIAL_BLOB_SIZE #>]
        [String]$Pass,

     [Parameter(Mandatory=$false)]
        [ValidateLength(1,256) <# CRED_MAX_STRING_LENGTH #>]
        [String]$Comment,

     [Parameter(Mandatory=$false)]
        [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
        "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
        [String]$CredType = "GENERIC",

     [Parameter(Mandatory=$false)]
        [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
        [String]$CredPersist = "ENTERPRISE"
    )

    #region Pinvoke
    #region Inline C#
    [String] $PsCredmanUtils = @"
    using System;
    using System.Runtime.InteropServices;

    namespace PsUtils
    {
        public class CredMan
        {
            #region Imports
            // DllImport derives from System.Runtime.InteropServices
            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
            private static extern bool CredDeleteW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredEnumerateW", CharSet = CharSet.Unicode)]
            private static extern bool CredEnumerateW([In] string Filter, [In] int Flags, out int Count, out IntPtr CredentialPtr);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
            private static extern void CredFree([In] IntPtr cred);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
            private static extern bool CredReadW([In] string target, [In] CRED_TYPE type, [In] int reservedFlag, out IntPtr CredentialPtr);

            [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
            private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);
            #endregion

            #region Fields
            public enum CRED_FLAGS : uint
            {
                NONE = 0x0,
                PROMPT_NOW = 0x2,
                USERNAME_TARGET = 0x4
            }

            public enum CRED_ERRORS : uint
            {
                ERROR_SUCCESS = 0x0,
                ERROR_INVALID_PARAMETER = 0x80070057,
                ERROR_INVALID_FLAGS = 0x800703EC,
                ERROR_NOT_FOUND = 0x80070490,
                ERROR_NO_SUCH_LOGON_SESSION = 0x80070520,
                ERROR_BAD_USERNAME = 0x8007089A
            }

            public enum CRED_PERSIST : uint
            {
                SESSION = 1,
                LOCAL_MACHINE = 2,
                ENTERPRISE = 3
            }

            public enum CRED_TYPE : uint
            {
                GENERIC = 1,
                DOMAIN_PASSWORD = 2,
                DOMAIN_CERTIFICATE = 3,
                DOMAIN_VISIBLE_PASSWORD = 4,
                GENERIC_CERTIFICATE = 5,
                DOMAIN_EXTENDED = 6,
                MAXIMUM = 7,      // Maximum supported cred type
                MAXIMUM_EX = (MAXIMUM + 1000),  // Allow new applications to run on old OSes
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct Credential
            {
                public CRED_FLAGS Flags;
                public CRED_TYPE Type;
                public string TargetName;
                public string Comment;
                public DateTime LastWritten;
                public UInt32 CredentialBlobSize;
                public string CredentialBlob;
                public CRED_PERSIST Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public string TargetAlias;
                public string UserName;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private struct NativeCredential
            {
                public CRED_FLAGS Flags;
                public CRED_TYPE Type;
                public IntPtr TargetName;
                public IntPtr Comment;
                public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
                public UInt32 CredentialBlobSize;
                public IntPtr CredentialBlob;
                public UInt32 Persist;
                public UInt32 AttributeCount;
                public IntPtr Attributes;
                public IntPtr TargetAlias;
                public IntPtr UserName;
            }
            #endregion

            #region Child Class
            private class CriticalCredentialHandle : Microsoft.Win32.SafeHandles.CriticalHandleZeroOrMinusOneIsInvalid
            {
                public CriticalCredentialHandle(IntPtr preexistingHandle)
                {
                    SetHandle(preexistingHandle);
                }

                private Credential XlateNativeCred(IntPtr pCred)
                {
                    NativeCredential ncred = (NativeCredential)Marshal.PtrToStructure(pCred, typeof(NativeCredential));
                    Credential cred = new Credential();
                    cred.Type = ncred.Type;
                    cred.Flags = ncred.Flags;
                    cred.Persist = (CRED_PERSIST)ncred.Persist;

                    long LastWritten = ncred.LastWritten.dwHighDateTime;
                    LastWritten = (LastWritten << 32) + ncred.LastWritten.dwLowDateTime;
                    cred.LastWritten = DateTime.FromFileTime(LastWritten);

                    cred.UserName = Marshal.PtrToStringUni(ncred.UserName);
                    cred.TargetName = Marshal.PtrToStringUni(ncred.TargetName);
                    cred.TargetAlias = Marshal.PtrToStringUni(ncred.TargetAlias);
                    cred.Comment = Marshal.PtrToStringUni(ncred.Comment);
                    cred.CredentialBlobSize = ncred.CredentialBlobSize;
                    if (0 < ncred.CredentialBlobSize)
                    {
                        cred.CredentialBlob = Marshal.PtrToStringUni(ncred.CredentialBlob, (int)ncred.CredentialBlobSize / 2);
                    }
                    return cred;
                }

                public Credential GetCredential()
                {
                    if (IsInvalid)
                    {
                        throw new InvalidOperationException("Invalid CriticalHandle!");
                    }
                    Credential cred = XlateNativeCred(handle);
                    return cred;
                }

                public Credential[] GetCredentials(int count)
                {
                    if (IsInvalid)
                    {
                        throw new InvalidOperationException("Invalid CriticalHandle!");
                    }
                    Credential[] Credentials = new Credential[count];
                    IntPtr pTemp = IntPtr.Zero;
                    for (int inx = 0; inx < count; inx++)
                    {
                        pTemp = Marshal.ReadIntPtr(handle, inx * IntPtr.Size);
                        Credential cred = XlateNativeCred(pTemp);
                        Credentials[inx] = cred;
                    }
                    return Credentials;
                }

                override protected bool ReleaseHandle()
                {
                    if (IsInvalid)
                    {
                        return false;
                    }
                    CredFree(handle);
                    SetHandleAsInvalid();
                    return true;
                }
            }
            #endregion

            #region Custom API
            public static int CredDelete(string target, CRED_TYPE type)
            {
                if (!CredDeleteW(target, type, 0))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                return 0;
            }

            public static int CredEnum(string Filter, out Credential[] Credentials)
            {
                int count = 0;
                int Flags = 0x0;
                if (string.IsNullOrEmpty(Filter) ||
                    "*" == Filter)
                {
                    Filter = null;
                    if (6 <= Environment.OSVersion.Version.Major)
                    {
                        Flags = 0x1; //CRED_ENUMERATE_ALL_CREDENTIALS; only valid is OS >= Vista
                    }
                }
                IntPtr pCredentials = IntPtr.Zero;
                if (!CredEnumerateW(Filter, Flags, out count, out pCredentials))
                {
                    Credentials = null;
                    return Marshal.GetHRForLastWin32Error(); 
                }
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredentials);
                Credentials = CredHandle.GetCredentials(count);
                return 0;
            }

            public static int CredRead(string target, CRED_TYPE type, out Credential Credential)
            {
                IntPtr pCredential = IntPtr.Zero;
                Credential = new Credential();
                if (!CredReadW(target, type, 0, out pCredential))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                CriticalCredentialHandle CredHandle = new CriticalCredentialHandle(pCredential);
                Credential = CredHandle.GetCredential();
                return 0;
            }

            public static int CredWrite(Credential userCredential)
            {
                if (!CredWriteW(ref userCredential, 0))
                {
                    return Marshal.GetHRForLastWin32Error();
                }
                return 0;
            }

            #endregion

            private static int AddCred()
            {
                Credential Cred = new Credential();
                string Password = "Password";
                Cred.Flags = 0;
                Cred.Type = CRED_TYPE.GENERIC;
                Cred.TargetName = "Target";
                Cred.UserName = "UserName";
                Cred.AttributeCount = 0;
                Cred.Persist = CRED_PERSIST.ENTERPRISE;
                Cred.CredentialBlobSize = (uint)Password.Length;
                Cred.CredentialBlob = Password;
                Cred.Comment = "Comment";
                return CredWrite(Cred);
            }

            private static bool CheckError(string TestName, CRED_ERRORS Rtn)
            {
                switch(Rtn)
                {
                    case CRED_ERRORS.ERROR_SUCCESS:
                        Console.WriteLine(string.Format("'{0}' worked", TestName));
                        return true;
                    case CRED_ERRORS.ERROR_INVALID_FLAGS:
                    case CRED_ERRORS.ERROR_INVALID_PARAMETER:
                    case CRED_ERRORS.ERROR_NO_SUCH_LOGON_SESSION:
                    case CRED_ERRORS.ERROR_NOT_FOUND:
                    case CRED_ERRORS.ERROR_BAD_USERNAME:
                        Console.WriteLine(string.Format("'{0}' failed; {1}.", TestName, Rtn));
                        break;
                    default:
                        Console.WriteLine(string.Format("'{0}' failed; 0x{1}.", TestName, Rtn.ToString("X")));
                        break;
                }
                return false;
            }

            /*
             * Note: the Main() function is primarily for debugging and testing in a Visual 
             * Studio session.  Although it will work from PowerShell, it's not very useful.
             */
            public static void Main()
            {
                Credential[] Creds = null;
                Credential Cred = new Credential();
                int Rtn = 0;

                Console.WriteLine("Testing CredWrite()");
                Rtn = AddCred();
                if (!CheckError("CredWrite", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredEnum()");
                Rtn = CredEnum(null, out Creds);
                if (!CheckError("CredEnum", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredRead()");
                Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredDelete()");
                Rtn = CredDelete("Target", CRED_TYPE.GENERIC);
                if (!CheckError("CredDelete", (CRED_ERRORS)Rtn))
                {
                    return;
                }
                Console.WriteLine("Testing CredRead() again");
                Rtn = CredRead("Target", CRED_TYPE.GENERIC, out Cred);
                if (!CheckError("CredRead", (CRED_ERRORS)Rtn))
                {
                    Console.WriteLine("if the error is 'ERROR_NOT_FOUND', this result is OK.");
                }
            }
        }
    }
"@
    #endregion

    $PsCredMan = $null
    try
    {
     $PsCredMan = [PsUtils.CredMan]
    }
    catch
    {
     #only remove the error we generate
     try {$Error.RemoveAt($Error.Count-1)} catch {Write-Verbose "No past errors yet..."}
    
    }
    if($null -eq $PsCredMan)
    {
     Add-Type $PsCredmanUtils
    }
    #endregion

    #region Internal Tools
    [HashTable] $ErrorCategory = @{0x80070057 = "InvalidArgument";
                                   0x800703EC = "InvalidData";
                                   0x80070490 = "ObjectNotFound";
                                   0x80070520 = "SecurityError";
                                   0x8007089A = "SecurityError"}

    function Get-CredType {
     Param (
      [Parameter(Mandatory=$true)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType
     )
     
     switch($CredType) {
      "GENERIC" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC}
      "DOMAIN_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_PASSWORD}
      "DOMAIN_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_CERTIFICATE}
      "DOMAIN_VISIBLE_PASSWORD" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_VISIBLE_PASSWORD}
      "GENERIC_CERTIFICATE" {return [PsUtils.CredMan+CRED_TYPE]::GENERIC_CERTIFICATE}
      "DOMAIN_EXTENDED" {return [PsUtils.CredMan+CRED_TYPE]::DOMAIN_EXTENDED}
      "MAXIMUM" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM}
      "MAXIMUM_EX" {return [PsUtils.CredMan+CRED_TYPE]::MAXIMUM_EX}
     }
    }

    function Get-CredPersist {
     Param (
      [Parameter(Mandatory=$true)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String] $CredPersist
     )
     
     switch($CredPersist) {
      "SESSION" {return [PsUtils.CredMan+CRED_PERSIST]::SESSION}
      "LOCAL_MACHINE" {return [PsUtils.CredMan+CRED_PERSIST]::LOCAL_MACHINE}
      "ENTERPRISE" {return [PsUtils.CredMan+CRED_PERSIST]::ENTERPRISE}
     }
    }
    #endregion

    #region Dot-Sourced API
    function Del-Creds {
        <#
        .Synopsis
            Deletes the specified credentials

        .Description
            Calls Win32 CredDeleteW via [PsUtils.CredMan]::CredDelete

        .INPUTS
            See function-level notes

        .OUTPUTS
            0 or non-0 according to action success
            [Management.Automation.ErrorRecord] if error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

     Param (
      [Parameter(Mandatory=$true)]
            [ValidateLength(1,32767)]
            [String] $Target,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String] $CredType = "GENERIC"
     )
     
     [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredDelete($Target, $(Get-CredType $CredType))
     }
     catch {
      return $_
     }
     if(0 -ne $Results) {
      [String]$Msg = "Failed to delete credentials store for target '$Target'"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
      return $ErrRcd
     }
     return $Results
    }

    function Enum-Creds {
        <#
        .Synopsis
          Enumerates stored credentials for operating user

        .Description
          Calls Win32 CredEnumerateW via [PsUtils.CredMan]::CredEnum

        .INPUTS
          
        .OUTPUTS
          [PsUtils.CredMan+Credential[]] if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Filter
          Specifies the filter to be applied to the query
          Defaults to [String]::Empty
          
        #>

     Param (
      [Parameter(Mandatory=$false)]
            [AllowEmptyString()]
            [String]$Filter = [String]::Empty
     )
     
     [PsUtils.CredMan+Credential[]]$Creds = [Array]::CreateInstance([PsUtils.CredMan+Credential], 0)
     [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredEnum($Filter, [Ref]$Creds)
     }
     catch {
      return $_
     }
     switch($Results) {
            0 {break}
            0x80070490 {break} #ERROR_NOT_FOUND
            default {
          [String]$Msg = "Failed to enumerate credentials store for user '$Env:UserName'"
          [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
          [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
          return $ErrRcd
            }
     }
     return $Creds
    }

    function Read-Creds {
        <#
        .Synopsis
            Reads specified credentials for operating user

        .Description
            Calls Win32 CredReadW via [PsUtils.CredMan]::CredRead

        .INPUTS

        .OUTPUTS
            [PsUtils.CredMan+Credential] if successful
            [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
            Specifies the URI for which the credentials are associated
            If not provided, the username is used as the target
          
        .PARAMETER CredType
            Specifies the desired credentials type; defaults to 
            "CRED_TYPE_GENERIC"
        #>

     Param (
      [Parameter(Mandatory=$true)]
            [ValidateLength(1,32767)]
            [String]$Target,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC"
     )
     
        #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
     if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) { 
      [String]$Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
      [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
      return $ErrRcd
     }
     [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
        [Int]$Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredRead($Target, $(Get-CredType $CredType), [Ref]$Cred)
     }
     catch {
      return $_
     }
     
     switch($Results) {
            0 {break}
            0x80070490 {return $null} #ERROR_NOT_FOUND
            default {
          [String] $Msg = "Error reading credentials for target '$Target' from '$Env:UserName' credentials store"
          [Management.ManagementException]$MgmtException = New-Object Management.ManagementException($Msg)
          [Management.Automation.ErrorRecord]$ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
          return $ErrRcd
            }
     }
     return $Cred
    }

    function Write-Creds {
        <#
        .Synopsis
          Saves or updates specified credentials for operating user

        .Description
          Calls Win32 CredWriteW via [PsUtils.CredMan]::CredWrite

        .INPUTS

        .OUTPUTS
          [Boolean] true if successful
          [Management.Automation.ErrorRecord] if unsuccessful or error encountered

        .PARAMETER Target
          Specifies the URI for which the credentials are associated
          If not provided, the username is used as the target
          
        .PARAMETER UserName
          Specifies the name of credential to be read
          
        .PARAMETER Password
          Specifies the password of credential to be read
          
        .PARAMETER Comment
          Allows the caller to specify the comment associated with 
          these credentials
          
        .PARAMETER CredType
          Specifies the desired credentials type; defaults to 
          "CRED_TYPE_GENERIC"

        .PARAMETER CredPersist
          Specifies the desired credentials storage type;
          defaults to "CRED_PERSIST_ENTERPRISE"
        #>

     Param (
      [Parameter(Mandatory=$false)]
            [ValidateLength(0,32676)]
            [String]$Target,

      [Parameter(Mandatory=$true)]
            [ValidateLength(1,512)]
            [String]$UserName,

      [Parameter(Mandatory=$true)]
            [ValidateLength(1,512)]
            [String]$Password,

      [Parameter(Mandatory=$false)]
            [ValidateLength(0,256)]
            [String]$Comment = [String]::Empty,

      [Parameter(Mandatory=$false)]
            [ValidateSet("GENERIC","DOMAIN_PASSWORD","DOMAIN_CERTIFICATE","DOMAIN_VISIBLE_PASSWORD",
      "GENERIC_CERTIFICATE","DOMAIN_EXTENDED","MAXIMUM","MAXIMUM_EX")]
            [String]$CredType = "GENERIC",

      [Parameter(Mandatory=$false)]
            [ValidateSet("SESSION","LOCAL_MACHINE","ENTERPRISE")]
            [String]$CredPersist = "ENTERPRISE"
     )

     if ([String]::IsNullOrEmpty($Target)) {
      $Target = $UserName
     }
        #CRED_MAX_DOMAIN_TARGET_NAME_LENGTH
     if ("GENERIC" -ne $CredType -and 337 -lt $Target.Length) {
      [String] $Msg = "Target field is longer ($($Target.Length)) than allowed (max 337 characters)"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, 666, 'LimitsExceeded', $null)
      return $ErrRcd
     }
        if ([String]::IsNullOrEmpty($Comment)) {
            $Comment = [String]::Format("Last edited by {0}\{1} on {2}",$Env:UserDomain,$Env:UserName,$Env:ComputerName)
        }
     [String]$DomainName = [Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
     [PsUtils.CredMan+Credential]$Cred = New-Object PsUtils.CredMan+Credential
     
        switch($Target -eq $UserName -and 
        $("CRED_TYPE_DOMAIN_PASSWORD" -eq $CredType -or "CRED_TYPE_DOMAIN_CERTIFICATE" -eq $CredType)) {
      $true  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::USERNAME_TARGET}
      $false  {$Cred.Flags = [PsUtils.CredMan+CRED_FLAGS]::NONE}
     }
     $Cred.Type = Get-CredType $CredType
     $Cred.TargetName = $Target
     $Cred.UserName = $UserName
     $Cred.AttributeCount = 0
     $Cred.Persist = Get-CredPersist $CredPersist
     $Cred.CredentialBlobSize = [Text.Encoding]::Unicode.GetBytes($Password).Length
     $Cred.CredentialBlob = $Password
     $Cred.Comment = $Comment

     [Int] $Results = 0
     try {
      $Results = [PsUtils.CredMan]::CredWrite($Cred)
     }
     catch {
      return $_
     }

     if(0 -ne $Results) {
      [String] $Msg = "Failed to write to credentials store for target '$Target' using '$UserName', '$Password', '$Comment'"
      [Management.ManagementException] $MgmtException = New-Object Management.ManagementException($Msg)
      [Management.Automation.ErrorRecord] $ErrRcd = New-Object Management.Automation.ErrorRecord($MgmtException, $Results.ToString("X"), $ErrorCategory[$Results], $null)
      return $ErrRcd
     }
     return $Results
    }

    #endregion

    #region Cmd-Line functionality
    function CredManMain {
    #region Adding credentials
     if ($AddCred) {
      if([String]::IsNullOrEmpty($User) -or [String]::IsNullOrEmpty($Pass)) {
       Write-Host "You must supply a user name and password (target URI is optional)."
       return
      }
      # may be [Int32] or [Management.Automation.ErrorRecord]
      [Object]$Results = Write-Creds $Target $User $Pass $Comment $CredType $CredPersist
      if (0 -eq $Results) {
       [Object]$Cred = Read-Creds $Target $CredType
       if ($null -eq $Cred) {
        Write-Host "Credentials for '$Target', '$User' was not found."
        return
       }
       if ($Cred -is [Management.Automation.ErrorRecord]) {
        return $Cred
       }

                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                )

       return $AddedCredentialsObject
      }
      # will be a [Management.Automation.ErrorRecord]
      return $Results
     }
    #endregion 

    #region Removing credentials
     if ($DelCred) {
      if (-not $Target) {
       Write-Host "You must supply a target URI."
       return
      }
      # may be [Int32] or [Management.Automation.ErrorRecord]
      [Object]$Results = Del-Creds $Target $CredType 
      if (0 -eq $Results) {
       Write-Host "Successfully deleted credentials for '$Target'"
       return
      }
      # will be a [Management.Automation.ErrorRecord]
      return $Results
     }
    #endregion

    #region Reading selected credential
     if ($GetCred) {
      if(-not $Target) {
       Write-Host "You must supply a target URI."
       return
      }
      # may be [PsUtils.CredMan+Credential] or [Management.Automation.ErrorRecord]
      [Object]$Cred = Read-Creds $Target $CredType
      if ($null -eq $Cred) {
       Write-Host "Credential for '$Target' as '$CredType' type was not found."
       return
      }
      if ($Cred -is [Management.Automation.ErrorRecord]) {
       return $Cred
      }

            New-Variable -Name "AddedCredentialsObject" -Value $(
                [pscustomobject][ordered]@{
                    UserName    = $($Cred.UserName)
                    Password    = $($Cred.CredentialBlob)
                    Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                    Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                    Comment     = $($Cred.Comment)
                }
            )

            return $AddedCredentialsObject
     }
    #endregion

    #region Reading all credentials
     if ($ShoCred) {
      # may be [PsUtils.CredMan+Credential[]] or [Management.Automation.ErrorRecord]
      [Object]$Creds = Enum-Creds
      if ($Creds -split [Array] -and 0 -eq $Creds.Length) {
       Write-Host "No Credentials found for $($Env:UserName)"
       return
      }
      if ($Creds -is [Management.Automation.ErrorRecord]) {
       return $Creds
      }

            $ArrayOfCredObjects = @()
      foreach($Cred in $Creds) {
                New-Variable -Name "AddedCredentialsObject" -Value $(
                    [pscustomobject][ordered]@{
                        UserName    = $($Cred.UserName)
                        Password    = $($Cred.CredentialBlob)
                        Target      = $($Cred.TargetName.Substring($Cred.TargetName.IndexOf("=")+1))
                        Updated     = "$([String]::Format('{0:yyyy-MM-dd HH:mm:ss}', $Cred.LastWritten.ToUniversalTime())) UTC"
                        Comment     = $($Cred.Comment)
                    }
                ) -Force

                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Alias" -Value "$($Cred.TargetAlias)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "AttribCnt" -Value "$($Cred.AttributeCount)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Attribs" -Value "$($Cred.Attributes)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Flags" -Value "$($Cred.Flags)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "PwdSize" -Value "$($Cred.CredentialBlobSize)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Storage" -Value "$($Cred.Persist)"
                $AddedCredentialsObject | Add-Member -MemberType NoteProperty -Name "Type" -Value "$($Cred.Type)"

                $ArrayOfCredObjects +=, $AddedCredentialsObject
      }
      return $ArrayOfCredObjects
     }
    #endregion

    #region Run basic diagnostics
     if($RunTests) {
      [PsUtils.CredMan]::Main()
     }
    #endregion
    }
    #endregion

    CredManMain
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUbDYKScCADsF78mzuwbBfgZ52
# 4ICgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJ7qGQ/xKYZnUiav
# A7tnQzNI4EomMA0GCSqGSIb3DQEBAQUABIIBAJRiD8vk7utoUlN7ESYwfvr7dOvB
# k5R2iGIvJJkdOnd5vXQ6YqLxMKIXxpg5Vn6xwL+PmTwD0QY53ABBEoVkIu3zGZ1s
# D4rHuBj2GHMq+IZ7c0ekjK9QKHvMAbdGzrcLNGRWhlnmOVxSIgqmx1WHPIX595+x
# RUUM2WgjnGDVfJd9s3OIDoEoTv1Kik92Mli5WsJjLT+KurQY7Vqp241/WFD/Jq6C
# 8t30hg/mBEOEuzVvow8U+msDeNU0GGCfuEsSGxFC324Z919/sAGXoCrwC4sY1Tni
# qHUDGhZDvUvmFafFFOZ10ZT3ITG4NAyvyOd99LQqHqvf4sn4XIPnYXcMzNA=
# SIG # End signature block
