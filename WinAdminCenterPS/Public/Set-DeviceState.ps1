<#

    .SYNOPSIS
        Sets the state of a device to enabled or disabled.

    .DESCRIPTION
        Sets the state of a device to enabled or disabled.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function Set-DeviceState {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ClassGuid,

        [Parameter(Mandatory = $true)]
        [String]
        $DeviceInstancePath,

        [Switch]
        $Enable,

        [Switch]
        $Disable
    )

    if ($Enable -and $Disable) {
        Throw
    } else {
        Add-Type -ErrorAction SilentlyContinue -Language CSharp @"
namespace SME.DeviceManager
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;
    using Microsoft.Win32.SafeHandles;

    [Flags()]
    internal enum Scopes
    {
        Global = 1,
        ConfigSpecific = 2,
        ConfigGeneral = 4
    }

    internal enum DeviceFunction
    {
        SelectDevice = 1,
        InstallDevice = 2,
        AssignResources = 3,
        Properties = 4,
        Remove = 5,
        FirstTimeSetup = 6,
        FoundDevice = 7,
        SelectClassDrivers = 8,
        ValidateClassDrivers = 9,
        InstallClassDrivers = 10,
        CalcDiskSpace = 11,
        DestroyPrivateData = 12,
        ValidateDriver = 13,
        Detect = 15,
        InstallWizard = 16,
        DestroyWizardData = 17,
        PropertyChange = 18,
        EnableClass = 19,
        DetectVerify = 20,
        InstallDeviceFiles = 21,
        UnRemove = 22,
        SelectBestCompatDrv = 23,
        AllowInstall = 24,
        RegisterDevice = 25,
        NewDeviceWizardPreSelect = 26,
        NewDeviceWizardSelect = 27,
        NewDeviceWizardPreAnalyze = 28,
        NewDeviceWizardPostAnalyze = 29,
        NewDeviceWizardFinishInstall = 30,
        Unused1 = 31,
        InstallInterfaces = 32,
        DetectCancel = 33,
        RegisterCoInstallers = 34,
        AddPropertyPageAdvanced = 35,
        AddPropertyPageBasic = 36,
        Reserved1 = 37,
        Troubleshooter = 38,
        PowerMessageWake = 39,
        AddRemotePropertyPageAdvanced = 40,
        UpdateDriverUI = 41,
        Reserved2 = 48
    }

    internal enum DeviceStateAction
    {
        Enable = 1,
        Disable = 2,
        PropChange = 3,
        Start = 4,
        Stop = 5
    }

    [Flags()]
    internal enum SetupDiGetClassDevsFlags
    {
        Default = 1,
        Present = 2,
        AllClasses = 4,
        Profile = 8,
        DeviceInterface = 16
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeviceInfoData
    {
        public int Size;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PropertyChangeParameters
    {
        public int Size;
        public DeviceFunction DeviceFunction;
        public DeviceStateAction StateChange;
        public Scopes Scope;
        public int HwProfile;
    }

    internal static class NativeMethods
    {
        private const string setupApiDll = "setupapi.dll";

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiCallClassInstaller(DeviceFunction installFunction, MySafeHandle deviceInfoSet, [In()]ref DeviceInfoData deviceInfoData);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiEnumDeviceInfo(MySafeHandle deviceInfoSet, int memberIndex, ref DeviceInfoData deviceInfoData);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern MySafeHandle SetupDiGetClassDevs([In()]ref Guid classGuid, [MarshalAs(UnmanagedType.LPWStr)]string enumerator, IntPtr hwndParent, SetupDiGetClassDevsFlags flags);

        [DllImport(setupApiDll, SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet, ref DeviceInfoData did, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder DeviceInstanceId, int DeviceInstanceIdSize,out int RequiredSize);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiSetClassInstallParams(MySafeHandle deviceInfoSet, [In()]ref DeviceInfoData deviceInfoData, [In()]ref PropertyChangeParameters classInstallParams, int classInstallParamsSize);
    }

    internal class MySafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public MySafeHandle(): base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.SetupDiDestroyDeviceInfoList(this.handle);
        }
    }

    public static class DeviceStateManager
    {
        private const int InvalidIndex = -1;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_SUCCESS = 0;

        public static int SetDeviceState(Guid classGuid, string instanceId, bool enable)
        {
            MySafeHandle safeHandle = null;
            try
            {
                safeHandle = NativeMethods.SetupDiGetClassDevs(ref classGuid, null, IntPtr.Zero, SetupDiGetClassDevsFlags.Present);
                DeviceInfoData[] diData = GetDeviceInfoData(safeHandle);

                int index = GetDeviceIndex(safeHandle, diData, instanceId);
                if (index == InvalidIndex)
                {
                    return Marshal.GetLastWin32Error();
                }

                return SetDeviceEnabledState(safeHandle, diData[index], enable);
            }
            finally
            {
                if (safeHandle != null)
                {
                    if (safeHandle.IsClosed == false)
                    {
                        safeHandle.Close();
                    }

                    safeHandle.Dispose();
                }
            }
        }

        private static DeviceInfoData[] GetDeviceInfoData(MySafeHandle handle)
        {
            List<DeviceInfoData> data = new List<DeviceInfoData>();
            DeviceInfoData did = new DeviceInfoData();
            int didSize = Marshal.SizeOf(did);
            did.Size = didSize;
            int index = 0;

            while (NativeMethods.SetupDiEnumDeviceInfo(handle, index, ref did))
            {
                data.Add(did);
                index += 1;
                did = new DeviceInfoData();
                did.Size = didSize;
            }

            return data.ToArray();
        }

        private static int GetDeviceIndex(MySafeHandle handle, DeviceInfoData[] diData, string instanceId)
        {
            for (int idx = 0; idx <= diData.Length - 1; idx++)
            {
                StringBuilder sb = new StringBuilder(1);
                int cchRequired = 0;

                bool bRetValue = NativeMethods.SetupDiGetDeviceInstanceId(handle.DangerousGetHandle(), ref diData[idx], sb, sb.Capacity, out cchRequired);
                if (bRetValue == false && Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER)
                {
                    sb.Capacity = cchRequired;
                    bRetValue = NativeMethods.SetupDiGetDeviceInstanceId(handle.DangerousGetHandle(), ref diData[idx], sb, sb.Capacity, out cchRequired);
                }

                if (!bRetValue)
                {
                    return InvalidIndex;
                }

                if (instanceId.Equals(sb.ToString()))
                {
                    return idx;
                }
            }

            return InvalidIndex;
        }

        private static int SetDeviceEnabledState(MySafeHandle handle, DeviceInfoData diData, bool enable)
        {
            PropertyChangeParameters parameters = new PropertyChangeParameters();
            parameters.Size = 8;
            parameters.DeviceFunction = DeviceFunction.PropertyChange;
            parameters.Scope = Scopes.Global;

            parameters.StateChange = enable ? DeviceStateAction.Enable : DeviceStateAction.Disable;

            bool bRetValue = NativeMethods.SetupDiSetClassInstallParams(handle, ref diData, ref parameters, Marshal.SizeOf(parameters));
            if (!bRetValue)
            {
                return Marshal.GetLastWin32Error();
            }

            bRetValue = NativeMethods.SetupDiCallClassInstaller(DeviceFunction.PropertyChange, handle, ref diData);
            if (!bRetValue)
            {
                return Marshal.GetLastWin32Error();
            }

            return ERROR_SUCCESS;
        }
    }
}

"@

        if ($Enable) {
            $enableDevice = $true
        } else {
            $enableDevice = $false
        }

        $guid = [Guid]($ClassGuid)
        [SME.DeviceManager.DeviceStateManager]::SetDeviceState($guid, $DeviceInstancePath, $enableDevice)
    }

}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU+YeTWmc2DJhhFGqLWFb5tXai
# fsugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHooRkkbZYf+2wL9
# hNAwj1Bf4NWUMA0GCSqGSIb3DQEBAQUABIIBACe4yif9El/tQ9bDU3eqFKyTvW23
# PjavtkknL002TFc4ImbPmyxGQFXYlLHd+9fA+GxSj1wS4B1CptgBR9OLZ9nDS1Zz
# KNDpSwjp36B0GpOSYH7umy3KdKwTd0LEZFXZIynV8RSZe9m1+nb10XAJUL1GyDOK
# RcC/OqvD3gIr8eu5MrT2gRIkVRS2BI9GZ69kJpUpYDhReDDrdrwIH/ZY4Idd4xvR
# qxs/Mf/+SB/fZ0C2Rx8ZjVlGFPhNT43rHmd2seL82veTKL7x0+WJJaJwEJaWVvIi
# eTJ7eQrBVJGmivs+6d6BAsNEcZgcpii+b9d1ve10RBBt2PyebdL6bWapA5U=
# SIG # End signature block
