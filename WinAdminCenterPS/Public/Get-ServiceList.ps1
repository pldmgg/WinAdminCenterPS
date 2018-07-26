<#

    .SYNOPSIS
        Get all services information details using native APIs where Windows Server Manager WMI provider is not available.

    .DESCRIPTION
        Get all services information details using native APIs where Windows Server Manager WMI provider is not available.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers

#>
function Get-ServiceList {
    $NativeServiceInfo = @"
namespace SMT
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security.Permissions;

    public static class Service
    {
        private enum ErrorCode
        {
            ERROR_INSUFFICIENT_BUFFER = 122
        }

        private enum ACCESS_MASK
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000
        }

        private enum ServiceInfoLevel
        {
            SC_ENUM_PROCESS_INFO = 0
        }

        private enum ConfigInfoLevel
        {
            SERVICE_CONFIG_DESCRIPTION = 0x01,
            SERVICE_CONFIG_FAILURE_ACTIONS = 0x02,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 0x03,
            SERVICE_CONFIG_TRIGGER_INFO = 0x08
        }

        private enum ServiceType
        {
            SERVICE_KERNEL_DRIVER = 0x1,
            SERVICE_FILE_SYSTEM_DRIVER = 0x2,
            SERVICE_WIN32_OWN_PROCESS = 0x10,
            SERVICE_WIN32_SHARE_PROCESS = 0x20,
            SERVICE_INTERACTIVE_PROCESS = 0x100,
            SERVICE_WIN32 = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)
        }

        private enum ServiceStateRequest
        {
            SERVICE_ACTIVE = 0x1,
            SERVICE_INACTIVE = 0x2,
            SERVICE_STATE_ALL = (SERVICE_ACTIVE | SERVICE_INACTIVE)
        }

        private enum ServiceControlManagerType
        {
            SC_MANAGER_CONNECT = 0x1,
            SC_MANAGER_CREATE_SERVICE = 0x2,
            SC_MANAGER_ENUMERATE_SERVICE = 0x4,
            SC_MANAGER_LOCK = 0x8,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x10,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x20,
            SC_MANAGER_ALL_ACCESS = ACCESS_MASK.STANDARD_RIGHTS_REQUIRED | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG
        }

        private enum ServiceAcessRight
        {
            SERVICE_QUERY_CONFIG = 0x00000001
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SERVICE_DESCRIPTION
        {
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpDescription;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SERVICE_DELAYED_AUTO_START_INFO
        {
            public bool fDelayedAutostart;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class SERVICE_TRIGGER_INFO
        {
            public UInt32 cTriggers;
            public IntPtr pTriggers;
            public IntPtr pReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class QUERY_SERVICE_CONFIG
        {
            public UInt32 dwServiceType;
            public UInt32 dwStartType;
            public UInt32 dwErrorControl;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpBinaryPathName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpLoadOrderGroup;
            public UInt32 dwTagId;
            public IntPtr lpDependencies;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpServiceStartName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpDisplayName;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        internal struct ENUM_SERVICE_STATUS_PROCESS
        {
            internal static readonly int SizePack4 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));

            /// <summary>
            /// sizeof(ENUM_SERVICE_STATUS_PROCESS) allow Packing of 8 on 64 bit machines
            /// </summary>
            internal static readonly int SizePack8 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS)) + 4;

            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            internal string pServiceName;

            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            internal string pDisplayName;

            internal SERVICE_STATUS_PROCESS ServiceStatus;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SERVICE_STATUS_PROCESS
        {
            public UInt32 serviceType;
            public UInt32 currentState;
            public UInt32 controlsAccepted;
            public UInt32 win32ExitCode;
            public UInt32 serviceSpecificExitCode;
            public UInt32 checkPoint;
            public UInt32 waitHint;
            public UInt32 processId;
            public UInt32 serviceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceDetail
        {
            public string Name;
            public string DisplayName;
            public string Description;
            public UInt32 StartupType;
            public bool IsDelayedAutoStart;
            public bool IsTriggered;
            public UInt32 SupportedControlCodes;
            public UInt32 Status;
            public UInt64 ExitCode;
            public string[] DependentServices;
        }

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenService(IntPtr hSCManager, String lpServiceName, UInt32 dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool EnumServicesStatusEx(IntPtr hSCManager,
            int infoLevel, int dwServiceType,
            int dwServiceState, IntPtr lpServices, UInt32 cbBufSize,
            out uint pcbBytesNeeded, out uint lpServicesReturned,
            ref uint lpResumeHandle, string pszGroupName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfigW")]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfig2W")]
        public static extern Boolean QueryServiceConfig2(IntPtr hService, UInt32 dwInfoLevel, IntPtr buffer, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        //  
        // This is an arbitrary number, the apis we call doesn't specify a maximum and could ask for more  
        // buffer space. The function will actually handles scenarios where this buffer  
        // is not big enough. This is just to enable an optimization that we don't call the system api's  
        // twice. 
        // According to QueryServiceConfig and QueryServiceConfig2 functions MSDN doc, the maximum size of the buffer is 8K bytes. 
        //  
        const UInt32 defaultPageSizeInBytes = 4096;

        static void Main(string[] args)
        {
            GetServiceDetail();
        }

        public static ServiceDetail[] GetServiceDetail()
        {
            List<ServiceDetail> results = new List<ServiceDetail>();
            UInt32 uiBytesNeeded;
            bool success;
            UInt32 currentConfigBufferSizeInBytes = defaultPageSizeInBytes;
            IntPtr pSrvConfigBuffer;

            //  
            // Open the service control manager with query and enumerate rights, required for getting the  
            // configuration information and enumerating the services & their dependent services  
            // 
            IntPtr databaseHandle = OpenSCManager(null, null,
                (uint)ServiceControlManagerType.SC_MANAGER_CONNECT | (uint)ServiceControlManagerType.SC_MANAGER_ENUMERATE_SERVICE);
            if (databaseHandle == IntPtr.Zero)
                throw new System.Runtime.InteropServices.ExternalException("Error OpenSCManager\n");

            ENUM_SERVICE_STATUS_PROCESS[] services = GetServicesStatus(databaseHandle);
            // Pre allocate buffer
            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
            try
            {
                foreach (ENUM_SERVICE_STATUS_PROCESS service in services)
                {
                    string serviceName = service.pServiceName;
                    IntPtr serviceHandle = OpenService(databaseHandle, serviceName, (uint)ServiceAcessRight.SERVICE_QUERY_CONFIG);
                    if (serviceHandle == IntPtr.Zero)
                        throw new System.Runtime.InteropServices.ExternalException("Error OpenService name:" + serviceName);
                    ServiceDetail item = new ServiceDetail();
                    item.Name = serviceName;
                    item.DisplayName = service.pDisplayName;
                    item.Status = service.ServiceStatus.currentState;
                    item.SupportedControlCodes = service.ServiceStatus.controlsAccepted;

                    //  
                    // Get the description of the service, if fail record just move on  
                    //  
                    success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        //Directly using Marshal.PtrToStringAuto(pSrvConfigBuffer) won't work here, have to use structure
                        SERVICE_DESCRIPTION descriptionStruct = new SERVICE_DESCRIPTION();
                        Marshal.PtrToStructure(pSrvConfigBuffer, descriptionStruct);
                        item.Description = descriptionStruct.lpDescription;
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig2 for SERVICE_CONFIG_DESCRIPTION of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    // Get the delayed auto start info, if fail just record and move on
                    success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        SERVICE_DELAYED_AUTO_START_INFO delayedStruct = new SERVICE_DELAYED_AUTO_START_INFO();
                        Marshal.PtrToStructure(pSrvConfigBuffer, delayedStruct);
                        item.IsDelayedAutoStart = delayedStruct.fDelayedAutostart;
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig2 for SERVICE_CONFIG_DELAYED_AUTO_START_INFO of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    // SERVICE_CONFIG_TRIGGER_INFO is only support Windows 7 and above, if fail just move on 
                    success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_TRIGGER_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_TRIGGER_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        SERVICE_TRIGGER_INFO triggerStruct = new SERVICE_TRIGGER_INFO();
                        Marshal.PtrToStructure(pSrvConfigBuffer, triggerStruct);
                        item.IsTriggered = triggerStruct.cTriggers > 0;
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig2 for SERVICE_CONFIG_TRIGGER_INFO of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    //  
                    // Get the service startup type and dependent services list, if fail just move on  
                    //
                    success = QueryServiceConfig(serviceHandle, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig(serviceHandle, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        QUERY_SERVICE_CONFIG configStruct = new QUERY_SERVICE_CONFIG();
                        Marshal.PtrToStructure(pSrvConfigBuffer, configStruct);
                        item.StartupType = configStruct.dwStartType;

                        List<string> dependents = new List<string>();
                        unsafe
                        {
                            // convert IntPtr to wchar_t(2 bytes) pointer
                            ushort* pCurrentDependent = (ushort*)configStruct.lpDependencies.ToPointer();
                            while (pCurrentDependent != null && *pCurrentDependent != '\0')
                            {
                                string sd = Marshal.PtrToStringAuto((IntPtr)pCurrentDependent);
                                dependents.Add(sd);
                                pCurrentDependent += sd.Length + 1;
                            }

                        }
                        item.DependentServices = dependents.ToArray();
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    CloseServiceHandle(serviceHandle);
                    results.Add(item);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pSrvConfigBuffer);
                CloseServiceHandle(databaseHandle);
            }

            return results.ToArray();
        }

        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        internal static ENUM_SERVICE_STATUS_PROCESS[] GetServicesStatus(IntPtr databaseHandle)
        {
            if (databaseHandle == IntPtr.Zero)
            {
                return null;
            }

            List<ENUM_SERVICE_STATUS_PROCESS> result = new List<ENUM_SERVICE_STATUS_PROCESS>();

            IntPtr buffer = IntPtr.Zero;
            uint uiBytesNeeded = 0;
            uint ServicesReturnedCount = 0;
            uint uiResumeHandle = 0;

            try
            {
                //The maximum size of this array is 256K bytes. Determine the required size first
                EnumServicesStatusEx(databaseHandle, (int)ServiceInfoLevel.SC_ENUM_PROCESS_INFO, (int)ServiceType.SERVICE_WIN32,
                    (int)ServiceStateRequest.SERVICE_STATE_ALL, IntPtr.Zero, 0, out uiBytesNeeded, out ServicesReturnedCount, ref uiResumeHandle, null);
                // allocate memory to receive the data for all services
                buffer = Marshal.AllocHGlobal((int)uiBytesNeeded);

                if (!EnumServicesStatusEx(databaseHandle, (int)ServiceInfoLevel.SC_ENUM_PROCESS_INFO, (int)ServiceType.SERVICE_WIN32,
                    (int)ServiceStateRequest.SERVICE_STATE_ALL, buffer, uiBytesNeeded, out uiBytesNeeded, out ServicesReturnedCount, ref uiResumeHandle, null))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                ENUM_SERVICE_STATUS_PROCESS serviceStatus;

                // 64 bit system has extra pack sizes
                if (IntPtr.Size == 8)
                {
                    long pointer = buffer.ToInt64();
                    for (int i = 0; i < (int)ServicesReturnedCount; i++)
                    {
                        serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(new IntPtr(pointer),
                         typeof(ENUM_SERVICE_STATUS_PROCESS));
                        result.Add(serviceStatus);

                        // incremement pointer to next struct
                        pointer += ENUM_SERVICE_STATUS_PROCESS.SizePack8;
                    }
                }
                else //32 bit
                {
                    int pointer = buffer.ToInt32();
                    for (int i = 0; i < (int)ServicesReturnedCount; i++)
                    {
                        serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(new IntPtr(pointer),
                         typeof(ENUM_SERVICE_STATUS_PROCESS));
                        result.Add(serviceStatus);

                        // incremement pointer to next struct
                        pointer += ENUM_SERVICE_STATUS_PROCESS.SizePack4;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return result.ToArray();
        }
    }
}
"@

    $cp = New-Object System.CodeDom.Compiler.CompilerParameters
    $cp.ReferencedAssemblies.AddRange(('System.dll', 'System.ComponentModel.dll', 'System.Runtime.InteropServices.dll'))
    $cp.CompilerOptions = '/unsafe'

    Add-Type -TypeDefinition $NativeServiceInfo -CompilerParameters $cp
    Remove-Variable NativeServiceInfo

    $NativeServices = [SMT.Service]::GetServiceDetail()
    return $NativeServices
}
