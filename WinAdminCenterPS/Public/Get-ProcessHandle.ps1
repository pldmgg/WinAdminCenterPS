<#

    .SYNOPSIS
        Gets the filtered information of all the Operating System handles.

    .DESCRIPTION
        Gets the filtered information of all the Operating System handles.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers

#>
function Get-ProcessHandle {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'processId')]
        [int]
        $processId,

        [Parameter(Mandatory = $true, ParameterSetName = 'handleSubstring')]
        [string]
        $handleSubstring
    )

    $SystemHandlesInfo = @"
namespace SME
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    public static class NativeMethods
    {
        internal enum SYSTEM_INFORMATION_CLASS : int
        {
            /// </summary>
            SystemHandleInformation = 16
        }

        [Flags]
        internal enum ProcessAccessFlags : int
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SystemHandle
        {
            public Int32 ProcessId;
            public Byte ObjectTypeNumber;
            public Byte Flags;
            public UInt16 Handle;
            public IntPtr Object;
            public Int32 GrantedAccess;
        }

        [Flags]
        public enum DuplicateOptions : int
        {
            NONE = 0,
            /// <summary>
            /// Closes the source handle. This occurs regardless of any error status returned.
            /// </summary>
            DUPLICATE_CLOSE_SOURCE = 0x00000001,
            /// <summary>
            /// Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
            /// </summary>
            DUPLICATE_SAME_ACCESS = 0x00000002
        }

        internal enum OBJECT_INFORMATION_CLASS : int
        {
            /// <summary>
            /// Returns a PUBLIC_OBJECT_BASIC_INFORMATION structure as shown in the following Remarks section.
            /// </summary>
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            /// <summary>
            /// Returns a PUBLIC_OBJECT_TYPE_INFORMATION structure as shown in the following Remarks section.
            /// </summary>
            ObjectTypeInformation = 2
        }

        public enum FileType : int
        {
            FileTypeChar = 0x0002,
            FileTypeDisk = 0x0001,
            FileTypePipe = 0x0003,
            FileTypeRemote = 0x8000,
            FileTypeUnknown = 0x0000,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct GENERIC_MAPPING
        {
            UInt32 GenericRead;
            UInt32 GenericWrite;
            UInt32 GenericExecute;
            UInt32 GenericAll;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public UInt32 TotalNumberOfObjects;
            public UInt32 TotalNumberOfHandles;
            public UInt32 TotalPagedPoolUsage;
            public UInt32 TotalNonPagedPoolUsage;
            public UInt32 TotalNamePoolUsage;
            public UInt32 TotalHandleTableUsage;
            public UInt32 HighWaterNumberOfObjects;
            public UInt32 HighWaterNumberOfHandles;
            public UInt32 HighWaterPagedPoolUsage;
            public UInt32 HighWaterNonPagedPoolUsage;
            public UInt32 HighWaterNamePoolUsage;
            public UInt32 HighWaterHandleTableUsage;
            public UInt32 InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public UInt32 ValidAccessMask;
            public Boolean SecurityRequired;
            public Boolean MaintainHandleCount;
            public UInt32 PoolType;
            public UInt32 DefaultPagedPoolCharge;
            public UInt32 DefaultNonPagedPoolCharge;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String Buffer;
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            Int32 SystemInformationLength,
            out Int32 ReturnedLength);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            Int32 dwProcessId);

        [DllImport("ntdll.dll")]
        internal static extern UInt32 NtQueryObject(
            Int32 Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            Int32 ObjectInformationLength,
            out Int32 ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            UInt32 dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInheritHandle,
            DuplicateOptions dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryFullProcessImageName([In]IntPtr hProcess, [In]Int32 dwFlags, [Out]StringBuilder exeName, ref Int32 size);

        [DllImport("psapi.dll")]
        public static extern UInt32 GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder baseName, UInt32 size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 QueryDosDevice(String lpDeviceName, System.Text.StringBuilder lpTargetPath, Int32 ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern FileType GetFileType(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        internal const Int32 STATUS_INFO_LENGTH_MISMATCH = unchecked((Int32)0xC0000004L);
        internal const Int32 STATUS_SUCCESS = 0x00000000;
    }

    public class SystemHandles
    {
        private Queue<SystemHandle> systemHandles;
        private Int32 processId;
        String fileNameToMatch;
        Dictionary<Int32, IntPtr> processIdToHandle;
        Dictionary<Int32, String> processIdToImageName;
        private const Int32 GetObjectNameTimeoutMillis = 50;
        private Thread backgroundWorker;
        private static object syncRoot = new Object();

        public static IEnumerable<SystemHandle> EnumerateAllSystemHandles()
        {
            SystemHandles systemHandles = new SystemHandles();

            return systemHandles.Enumerate(HandlesEnumerationScope.AllSystemHandles);
        }
        public static IEnumerable<SystemHandle> EnumerateProcessSpecificHandles(Int32 processId)
        {
            SystemHandles systemHandles = new SystemHandles(processId);

            return systemHandles.Enumerate(HandlesEnumerationScope.ProcessSpecificHandles);
        }

        public static IEnumerable<SystemHandle> EnumerateMatchingFileNameHandles(String fileNameToMatch)
        {
            SystemHandles systemHandles = new SystemHandles(fileNameToMatch);

            return systemHandles.Enumerate(HandlesEnumerationScope.MatchingFileNameHandles);
        }

        private SystemHandles()
        { }

        public SystemHandles(Int32 processId)
        {
            this.processId = processId;
        }

        public SystemHandles(String fileNameToMatch)
        {
            this.fileNameToMatch = fileNameToMatch;
        }

        public IEnumerable<SystemHandle> Enumerate(HandlesEnumerationScope handlesEnumerationScope)
        {
            IEnumerable<SystemHandle> handles = null;

            this.backgroundWorker = new Thread(() => handles = Enumerate_Internal(handlesEnumerationScope));

            this.backgroundWorker.IsBackground = true;

            this.backgroundWorker.Start();

            return handles;
        }

        public bool IsBusy
        {
            get
            {
                return this.backgroundWorker.IsAlive;
            }
        }

        public bool WaitForEnumerationToComplete(int timeoutMillis)
        {
            return this.backgroundWorker.Join(timeoutMillis);
        }

        private IEnumerable<SystemHandle> Enumerate_Internal(HandlesEnumerationScope handlesEnumerationScope)
        {
            Int32 result;
            Int32 bufferLength = 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
            Int32 requiredLength;
            Int64 handleCount;
            Int32 offset = 0;
            IntPtr currentHandlePtr = IntPtr.Zero;
            NativeMethods.SystemHandle systemHandleStruct;
            Int32 systemHandleStructSize = 0;
            this.systemHandles = new Queue<SystemHandle>();
            this.processIdToHandle = new Dictionary<Int32, IntPtr>();
            this.processIdToImageName = new Dictionary<Int32, String>();

            while (true)
            {
                result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                    buffer,
                    bufferLength,
                    out requiredLength);

                if (result == NativeMethods.STATUS_SUCCESS)
                {
                    break;
                }
                else if (result == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferLength *= 2;
                    buffer = Marshal.AllocHGlobal(bufferLength);
                }
                else
                {
                    throw new InvalidOperationException(
                        String.Format(CultureInfo.InvariantCulture, "NtQuerySystemInformation failed with error code {0}", result));
                }
            } // End while loop.

            if (IntPtr.Size == 4)
            {
                handleCount = Marshal.ReadInt32(buffer);
            }
            else
            {
                handleCount = Marshal.ReadInt64(buffer);
            }

            offset = IntPtr.Size;
            systemHandleStruct = new NativeMethods.SystemHandle();
            systemHandleStructSize = Marshal.SizeOf(systemHandleStruct);

            if (handlesEnumerationScope == HandlesEnumerationScope.AllSystemHandles)
            {
                EnumerateAllSystemHandles(buffer, offset, systemHandleStructSize, handleCount);
            }
            else if (handlesEnumerationScope == HandlesEnumerationScope.ProcessSpecificHandles)
            {
                EnumerateProcessSpecificSystemHandles(buffer, offset, systemHandleStructSize, handleCount);
            }
            else if (handlesEnumerationScope == HandlesEnumerationScope.MatchingFileNameHandles)
            {
                this.EnumerateMatchingFileNameHandles(buffer, offset, systemHandleStructSize, handleCount);
            }

            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            this.Cleanup();

            return this.systemHandles;
        }

        public IEnumerable<SystemHandle> ExtractResults()
        {
            lock (syncRoot)
            {
                while (this.systemHandles.Count > 0)
                {
                    yield return this.systemHandles.Dequeue();
                }
            }
        }

        private void EnumerateAllSystemHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                ExamineCurrentHandle(currentHandleInfo);

                offset += systemHandleStructSize;
            }
        }

        private void EnumerateProcessSpecificSystemHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                if (currentHandleInfo.ProcessId == this.processId)
                {
                    ExamineCurrentHandle(currentHandleInfo);
                }

                offset += systemHandleStructSize;
            }
        }

        private void EnumerateMatchingFileNameHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                ExamineCurrentHandleForForMatchingFileName(currentHandleInfo, this.fileNameToMatch);

                offset += systemHandleStructSize;
            }
        }

        private void ExamineCurrentHandle(
            NativeMethods.SystemHandle currentHandleInfo)
        {
            IntPtr sourceProcessHandle = this.GetProcessHandle(currentHandleInfo.ProcessId);

            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            String processImageName = this.GetProcessImageName(currentHandleInfo.ProcessId, sourceProcessHandle);

            IntPtr duplicateHandle = CreateDuplicateHandle(sourceProcessHandle, (IntPtr)currentHandleInfo.Handle);

            if (duplicateHandle == IntPtr.Zero)
            {
                return;
            }

            String objectType = GetObjectType(duplicateHandle);

            String objectName = String.Empty;

            if (objectType != "File")
            {
                objectName = GetObjectName(duplicateHandle);
            }
            else
            {
                Thread getObjectNameThread = new Thread(() => objectName = GetObjectName(duplicateHandle));
                getObjectNameThread.IsBackground = true;
                getObjectNameThread.Start();

                if (false == getObjectNameThread.Join(GetObjectNameTimeoutMillis))
                {
                    getObjectNameThread.Abort();

                    getObjectNameThread.Join(GetObjectNameTimeoutMillis);

                    objectName = String.Empty;
                }
                else
                {
                    objectName = GetRegularFileName(objectName);
                }

                getObjectNameThread = null;
            }

            if (!String.IsNullOrWhiteSpace(objectType) &&
                !String.IsNullOrWhiteSpace(objectName))
            {
                SystemHandle systemHandle = new SystemHandle();
                systemHandle.TypeName = objectType;
                systemHandle.Name = objectName;
                systemHandle.ObjectTypeNumber = currentHandleInfo.ObjectTypeNumber;
                systemHandle.ProcessId = currentHandleInfo.ProcessId;
                systemHandle.ProcessImageName = processImageName;

                RegisterHandle(systemHandle);
            }

            NativeMethods.CloseHandle(duplicateHandle);
        }

        private void ExamineCurrentHandleForForMatchingFileName(
             NativeMethods.SystemHandle currentHandleInfo, String fileNameToMatch)
        {
            IntPtr sourceProcessHandle = this.GetProcessHandle(currentHandleInfo.ProcessId);

            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            String processImageName = this.GetProcessImageName(currentHandleInfo.ProcessId, sourceProcessHandle);

            if (String.IsNullOrWhiteSpace(processImageName))
            {
                return;
            }

            IntPtr duplicateHandle = CreateDuplicateHandle(sourceProcessHandle, (IntPtr)currentHandleInfo.Handle);

            if (duplicateHandle == IntPtr.Zero)
            {
                return;
            }

            String objectType = GetObjectType(duplicateHandle);

            String objectName = String.Empty;

            Thread getObjectNameThread = new Thread(() => objectName = GetObjectName(duplicateHandle));

            getObjectNameThread.IsBackground = true;

            getObjectNameThread.Start();

            if (false == getObjectNameThread.Join(GetObjectNameTimeoutMillis))
            {
                getObjectNameThread.Abort();

                getObjectNameThread.Join(GetObjectNameTimeoutMillis);

                objectName = String.Empty;
            }
            else
            {
                objectName = GetRegularFileName(objectName);
            }

            getObjectNameThread = null;


            if (!String.IsNullOrWhiteSpace(objectType) &&
                !String.IsNullOrWhiteSpace(objectName))
            {
                if (objectName.ToLower().Contains(fileNameToMatch.ToLower()))
                {
                    SystemHandle systemHandle = new SystemHandle();
                    systemHandle.TypeName = objectType;
                    systemHandle.Name = objectName;
                    systemHandle.ObjectTypeNumber = currentHandleInfo.ObjectTypeNumber;
                    systemHandle.ProcessId = currentHandleInfo.ProcessId;
                    systemHandle.ProcessImageName = processImageName;

                    RegisterHandle(systemHandle);
                }
            }

            NativeMethods.CloseHandle(duplicateHandle);
        }

        private void RegisterHandle(SystemHandle systemHandle)
        {
            lock (syncRoot)
            {
                this.systemHandles.Enqueue(systemHandle);
            }
        }

        private String GetObjectName(IntPtr duplicateHandle)
        {
            String objectName = String.Empty;
            IntPtr objectNameBuffer = IntPtr.Zero;

            try
            {
                Int32 objectNameBufferSize = 0x1000;
                objectNameBuffer = Marshal.AllocHGlobal(objectNameBufferSize);
                Int32 actualObjectNameLength;

                UInt32 queryObjectNameResult = NativeMethods.NtQueryObject(
                    duplicateHandle.ToInt32(),
                    NativeMethods.OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    objectNameBuffer,
                    objectNameBufferSize,
                    out actualObjectNameLength);

                if (queryObjectNameResult != 0 && actualObjectNameLength > 0)
                {
                    Marshal.FreeHGlobal(objectNameBuffer);
                    objectNameBufferSize = actualObjectNameLength;
                    objectNameBuffer = Marshal.AllocHGlobal(objectNameBufferSize);

                    queryObjectNameResult = NativeMethods.NtQueryObject(
                        duplicateHandle.ToInt32(),
                        NativeMethods.OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                        objectNameBuffer,
                        objectNameBufferSize,
                        out actualObjectNameLength);
                }

                // Get the name
                if (queryObjectNameResult == 0)
                {
                    NativeMethods.UNICODE_STRING name = (NativeMethods.UNICODE_STRING)Marshal.PtrToStructure(objectNameBuffer, typeof(NativeMethods.UNICODE_STRING));

                    objectName = name.Buffer;
                }
            }
            catch (ThreadAbortException)
            {
            }
            finally
            {
                if (objectNameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(objectNameBuffer);
                }
            }

            return objectName;
        }

        private String GetObjectType(IntPtr duplicateHandle)
        {
            String objectType = String.Empty;

            Int32 objectTypeBufferSize = 0x1000;
            IntPtr objectTypeBuffer = Marshal.AllocHGlobal(objectTypeBufferSize);
            Int32 actualObjectTypeLength;

            UInt32 queryObjectResult = NativeMethods.NtQueryObject(
                duplicateHandle.ToInt32(),
                NativeMethods.OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
                objectTypeBuffer,
                objectTypeBufferSize,
                out actualObjectTypeLength);

            if (queryObjectResult == 0)
            {
                NativeMethods.OBJECT_TYPE_INFORMATION typeInfo = (NativeMethods.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(objectTypeBuffer, typeof(NativeMethods.OBJECT_TYPE_INFORMATION));

                objectType = typeInfo.TypeName.Buffer;
            }

            if (objectTypeBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(objectTypeBuffer);
            }

            return objectType;
        }

        private IntPtr GetProcessHandle(Int32 processId)
        {
            if (this.processIdToHandle.ContainsKey(processId))
            {
                return this.processIdToHandle[processId];
            }

            IntPtr processHandle = NativeMethods.OpenProcess
                (NativeMethods.ProcessAccessFlags.DupHandle | NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.VMRead, false, processId);

            if (processHandle != IntPtr.Zero)
            {
                this.processIdToHandle.Add(processId, processHandle);
            }
            else
            {
                // throw new Win32Exception(Marshal.GetLastWin32Error());
                //  Console.WriteLine("UNABLE TO OPEN PROCESS {0}", processId);
            }

            return processHandle;
        }

        private String GetProcessImageName(Int32 processId, IntPtr handleToProcess)
        {
            if (this.processIdToImageName.ContainsKey(processId))
            {
                return this.processIdToImageName[processId];
            }

            Int32 bufferSize = 1024;

            String strProcessImageName = String.Empty;

            StringBuilder processImageName = new StringBuilder(bufferSize);

            NativeMethods.QueryFullProcessImageName(handleToProcess, 0, processImageName, ref bufferSize);

            strProcessImageName = processImageName.ToString();

            if (!String.IsNullOrWhiteSpace(strProcessImageName))
            {
                try
                {
                    strProcessImageName = Path.GetFileName(strProcessImageName);
                }
                catch
                {
                }

                this.processIdToImageName.Add(processId, strProcessImageName);
            }

            return strProcessImageName;
        }

        private IntPtr CreateDuplicateHandle(IntPtr sourceProcessHandle, IntPtr handleToDuplicate)
        {
            IntPtr currentProcessHandle = Process.GetCurrentProcess().Handle;

            IntPtr duplicateHandle = IntPtr.Zero;

            NativeMethods.DuplicateHandle(
                sourceProcessHandle,
                handleToDuplicate,
                currentProcessHandle,
                out duplicateHandle,
                0,
                false,
                NativeMethods.DuplicateOptions.DUPLICATE_SAME_ACCESS);

            return duplicateHandle;
        }

        private static String GetRegularFileName(String deviceFileName)
        {
            String actualFileName = String.Empty;

            if (!String.IsNullOrWhiteSpace(deviceFileName))
            {
                foreach (var logicalDrive in Environment.GetLogicalDrives())
                {
                    StringBuilder targetPath = new StringBuilder(4096);

                    if (0 == NativeMethods.QueryDosDevice(logicalDrive.Substring(0, 2), targetPath, 4096))
                    {
                        return targetPath.ToString();
                    }

                    String targetPathStr = targetPath.ToString();

                    if (deviceFileName.StartsWith(targetPathStr))
                    {
                        actualFileName = deviceFileName.Replace(targetPathStr, logicalDrive.Substring(0, 2));

                        break;

                    }
                }

                if (String.IsNullOrWhiteSpace(actualFileName))
                {
                    actualFileName = deviceFileName;
                }
            }

            return actualFileName;
        }

        private void Cleanup()
        {
            foreach (var processHandle in this.processIdToHandle.Values)
            {
                NativeMethods.CloseHandle(processHandle);
            }

            this.processIdToHandle.Clear();
        }
    }

    public class SystemHandle
    {
        public String Name { get; set; }
        public String TypeName { get; set; }
        public byte ObjectTypeNumber { get; set; }
        public Int32 ProcessId { get; set; }
        public String ProcessImageName { get; set; }
    }
  
    public enum HandlesEnumerationScope
    {
        AllSystemHandles,
        ProcessSpecificHandles,
        MatchingFileNameHandles
    }
}
"@

    ############################################################################################################################

    # Global settings for the script.

    ############################################################################################################################

    $ErrorActionPreference = "Stop"

    Set-StrictMode -Version 3.0

    ############################################################################################################################

    # Main script.

    ############################################################################################################################


    Add-Type -TypeDefinition $SystemHandlesInfo

    Remove-Variable SystemHandlesInfo

    if ($PSCmdlet.ParameterSetName -eq 'processId' -and $processId -ne $null) {

        $systemHandlesFinder = New-Object -TypeName SME.SystemHandles -ArgumentList $processId

        $scope = [SME.HandlesEnumerationScope]::ProcessSpecificHandles
    }

    elseif ($PSCmdlet.ParameterSetName -eq 'handleSubString') {
        
        $SystemHandlesFinder = New-Object -TypeName SME.SystemHandles -ArgumentList $handleSubstring

        $scope = [SME.HandlesEnumerationScope]::MatchingFileNameHandles
    }


    $SystemHandlesFinder.Enumerate($scope) | out-null

    while($SystemHandlesFinder.IsBusy)
    {
        $SystemHandlesFinder.ExtractResults() | Write-Output
        $SystemHandlesFinder.WaitForEnumerationToComplete(50) | out-null
    }

    $SystemHandlesFinder.ExtractResults() | Write-Output
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcv1mCA+8MrUdZGT8+PWlDSzV
# 5b+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFIBX3snKR7lI2dCh
# +Bvs+7wc4aUsMA0GCSqGSIb3DQEBAQUABIIBACn3znopCqPCNUGVYzLKUZaEB0e7
# lQjx//h/2qXdb2rFBrpChkBJK74D9AdNdzT4taef/LVc+eFtfWS5j7qUz5XQEKog
# UNiA+pUtJNCBfq0ZXwT2PG0GJL7jbMLCuU39bDFXXXrcp3U7y2uxqO9/WLzsV3DI
# upiZBj/OyRmmHbrumaFpomtw0Yj0dnTQs0cYQt8zJa5uW2MTdSmJFLXgG5Cs2F2I
# +qSgbDqG6JBbNt7Notv9iFwXa5Qf14kYswYS+rRW9i2M5jeDsjJIzdK9GbLKVxNr
# WuPWfcBTQiZFSU6BrbAXuKiy+HQVHXVqZm8LKQ8dgPfPQWx8q3AVMLueNIA=
# SIG # End signature block
