<#

    .SYNOPSIS
        Creates a new VHD.

    .DESCRIPTION
        Creates a new VHD.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

    .PARAMETER filePath
        The path to the VHD that will be created.

    .PARAMETER size
        The size of the VHD.

    .PARAMETER dynamic
        True for a dynamic VHD, false otherwise.

    .PARAMETER overwrite
        True to overwrite an existing VHD.

#>
function New-StorageVHD {
    param
    (
        # Path to the resultant vhd/vhdx file name.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $filepath,

        # The size of vhd/vhdx.
        [Parameter(Mandatory = $true)]
        [System.UInt64]
        $size,

        # Whether it is a dynamic vhd/vhdx.
        [Parameter(Mandatory = $true)]
        [Boolean]
        $dynamic,

        # Overwrite if already exists.
        [Boolean]
        $overwrite=$false
    )

    $NativeCode = @"
namespace SME
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.ComponentModel;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security;

    public static class VirtualDisk
    {
        const uint ERROR_SUCCESS = 0x0;

        const uint DEFAULT_SECTOR_SIZE = 0x200;

        const uint DEFAULT_BLOCK_SIZE = 0x200000;

        private static Guid VirtualStorageTypeVendorUnknown = new Guid("00000000-0000-0000-0000-000000000000");

        private static Guid VirtualStorageTypeVendorMicrosoft = new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SecurityDescriptor
        {
            public byte revision;
            public byte size;
            public short control;
            public IntPtr owner;
            public IntPtr group;
            public IntPtr sacl;
            public IntPtr dacl;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CreateVirtualDiskParametersV1
        {
            public CreateVirtualDiskVersion Version;
            public Guid UniqueId;
            public ulong MaximumSize;
            public uint BlockSizeInBytes;
            public uint SectorSizeInBytes;
            public string ParentPath;
            public string SourcePath;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CreateVirtualDiskParametersV2
        {
            public CreateVirtualDiskVersion Version;
            public Guid UniqueId;
            public ulong MaximumSize;
            public uint BlockSizeInBytes;
            public uint SectorSizeInBytes;
            public uint PhysicalSectorSizeInBytes;
            public string ParentPath;
            public string SourcePath;
            public OpenVirtualDiskFlags OpenFlags;
            public VirtualStorageType ParentVirtualStorageType;
            public VirtualStorageType SourceVirtualStorageType;
            public Guid ResiliencyGuid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct VirtualStorageType
        {
            public VirtualStorageDeviceType DeviceId;
            public Guid VendorId;
        }

        public enum CreateVirtualDiskVersion : int
        {
            VersionUnspecified = 0x0,
            Version1 = 0x1,
            Version2 = 0x2
        }

        public enum VirtualStorageDeviceType : int
        {
            Unknown = 0x0,
            Iso = 0x1,
            Vhd = 0x2,
            Vhdx = 0x3
        }

        [Flags]
        public enum OpenVirtualDiskFlags
        {
            None = 0x0,
            NoParents = 0x1,
            BlankFile = 0x2,
            BootDrive = 0x4,
        }

        [Flags]
        public enum VirtualDiskAccessMask
        {
            None = 0x00000000,
            AttachReadOnly = 0x00010000,
            AttachReadWrite = 0x00020000,
            Detach = 0x00040000,
            GetInfo = 0x00080000,
            Create = 0x00100000,
            MetaOperations = 0x00200000,
            Read = 0x000D0000,
            All = 0x003F0000,
            Writable = 0x00320000
        }

        [Flags]
        public enum CreateVirtualDiskFlags
        {
            None = 0x0,
            FullPhysicalAllocation = 0x1
        }

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint CreateVirtualDisk(
            [In, Out] ref VirtualStorageType VirtualStorageType,
            [In]          string Path,
            [In]          VirtualDiskAccessMask VirtualDiskAccessMask,
            [In, Out] ref SecurityDescriptor SecurityDescriptor,
            [In]          CreateVirtualDiskFlags Flags,
            [In]          uint ProviderSpecificFlags,
            [In, Out] ref CreateVirtualDiskParametersV2 Parameters,
            [In]          IntPtr Overlapped,
            [Out]     out SafeFileHandle Handle);

        [DllImport("advapi32", SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(
            [Out]     out SecurityDescriptor pSecurityDescriptor,
            [In]          uint dwRevision);


        public static void Create(string path, ulong size, bool dynamic, bool overwrite)
        {
            if(string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException("path");
            }

            // Validate size.  It needs to be a multiple of 512...  
            if ((size % 512) != 0)
            {
                throw (
                    new ArgumentOutOfRangeException(
                        "size",
                        size,
                        "The size of the virtual disk must be a multiple of 512."));
            }

            bool isVhd = false;

            VirtualStorageType virtualStorageType = new VirtualStorageType();
            virtualStorageType.VendorId = VirtualStorageTypeVendorMicrosoft;

            if (Path.GetExtension(path) == ".vhdx")
            {
                virtualStorageType.DeviceId = VirtualStorageDeviceType.Vhdx;
            }
            else if (Path.GetExtension(path) == ".vhd")
            {
                virtualStorageType.DeviceId = VirtualStorageDeviceType.Vhd;

                isVhd = true;
            }
            else
            {
                throw new ArgumentException("The path should have either of the following two extensions: .vhd or .vhdx");
            }

            if ((overwrite) && (System.IO.File.Exists(path)))
            {
                System.IO.File.Delete(path);
            }

            CreateVirtualDiskParametersV2 createParams = new CreateVirtualDiskParametersV2();
            createParams.Version = CreateVirtualDiskVersion.Version2;
            createParams.UniqueId = Guid.NewGuid();
            createParams.MaximumSize = size;
            createParams.BlockSizeInBytes = 0;
            createParams.SectorSizeInBytes = DEFAULT_SECTOR_SIZE;
            createParams.PhysicalSectorSizeInBytes = 0;
            createParams.ParentPath = null;
            createParams.SourcePath = null;
            createParams.OpenFlags = OpenVirtualDiskFlags.None;
            createParams.ParentVirtualStorageType = new VirtualStorageType();
            createParams.SourceVirtualStorageType = new VirtualStorageType();

            if(isVhd && dynamic)
            {
                createParams.BlockSizeInBytes = DEFAULT_BLOCK_SIZE;
            }

            CreateVirtualDiskFlags flags;

            if (dynamic)
            {
                flags = CreateVirtualDiskFlags.None;
            }
            else
            {
                flags = CreateVirtualDiskFlags.FullPhysicalAllocation;
            }

            SecurityDescriptor securityDescriptor;

            if (!InitializeSecurityDescriptor(out securityDescriptor, 1))
            {
                throw (
                    new SecurityException(
                        "Unable to initialize the security descriptor for the virtual disk."
                ));
            }

            SafeFileHandle vhdHandle = null;

            try
            {
                uint returnCode = CreateVirtualDisk(
                    ref virtualStorageType,
                        path,
                        VirtualDiskAccessMask.None,
                    ref securityDescriptor,
                        flags,
                        0,
                    ref createParams,
                        IntPtr.Zero,
                    out vhdHandle);

                if (ERROR_SUCCESS != returnCode)
                {
                    throw (new Win32Exception((int)returnCode));
                }
            }
            finally
            {
                if (vhdHandle != null && !vhdHandle.IsClosed)
                {
                    vhdHandle.Close();
                    vhdHandle.SetHandleAsInvalid();
                }
            }
        }
    }
}
"@

    ############################################################################################################################

    # Global settings for the script.

    ############################################################################################################################

    $ErrorActionPreference = "Stop"

    Set-StrictMode -Version 3.0

    Import-Module -Name Storage -Force -Global -WarningAction SilentlyContinue
    Import-Module Microsoft.PowerShell.Utility

    ############################################################################################################################

    # Main script.

    ############################################################################################################################

    Add-Type -TypeDefinition $NativeCode
    Remove-Variable NativeCode

    # Resolve $abc and ..\ from the File path.
    $filepath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExecutionContext.InvokeCommand.ExpandString($filepath))

    # Create the virtual disk drive.
    try
    {
        [SME.VirtualDisk]::Create($filepath, $size, $dynamic, $overwrite)
    }
    catch
    {
        if($_.Exception.InnerException)
        {
            throw $_.Exception.InnerException
        }
        elseif($_.Exception)
        {
            throw $_.Exception
        }
        else
        {
            throw $_
        }
    }

    # Mount the virtual disk drive.
    Mount-DiskImage -ImagePath $filepath


}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+kcUNTm3HeCp9+brMJuXnSwv
# Cxygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJBjRs02VIOCzaTX
# tiyWiBJAoMoNMA0GCSqGSIb3DQEBAQUABIIBAGMIztOhzXmqJ1ng3KXdk3/30hpy
# SsGHKjqJ+V5rFCYlME5Ms5MeRHJsfmEyGXcx3Y0Y5v4HHCE91zmAQ5+NdxXfeFoL
# I70vYGB71SGoJrNY/UNnOAlCQfqdlTTJCURGfXXUXjPEyQ6VVntakM/v+79kzko/
# yYM7G18EQWL0zQBHrnM6LqgeX/0IU/yUYUlbWcdVsCXKPffi4SFVBaBYLUD7kLVR
# my8vKG2uD/fYgaTxxrf70IhBpIKMm74BS4YftsHsaTmSSVo91P4tCQak97SVLQDa
# Gc0BCkrtjcULPtZapRLHu5Gi+cj8apiQBElSqx7N+NJ4GsJv0zxc4KVxzQ0=
# SIG # End signature block
