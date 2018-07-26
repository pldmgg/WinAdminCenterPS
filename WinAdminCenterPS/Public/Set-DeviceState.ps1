<#

    .SYNOPSIS
        Sets the state of a device to enabled or disabled.

    .DESCRIPTION
        Sets the state of a device to enabled or disabled.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
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