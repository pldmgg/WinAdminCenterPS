<#

    .SYNOPSIS
        Gets information about the processes running in downlevel computer.

    .DESCRIPTION
        Gets information about the processes running in downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers

#>
function Get-ProcessDownlevel {
    param
    (
        [Parameter(Mandatory = $true)]
        [boolean]
        $isLocal
    )

    $NativeProcessInfo = @"
namespace SMT
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.InteropServices;

    public class SystemProcess
    {
        public uint processId;
        public uint parentId;
        public string name;
        public string description;
        public string executablePath;
        public string userName;
        public string commandLine;
        public uint sessionId;
        public uint processStatus;
        public ulong cpuTime;
        public ulong cycleTime;
        public DateTime CreationDateTime;
        public ulong workingSetSize;
        public ulong peakWorkingSetSize;
        public ulong privateWorkingSetSize;
        public ulong sharedWorkingSetSize;
        public ulong commitCharge;
        public ulong pagedPool;
        public ulong nonPagedPool;
        public uint pageFaults;
        public uint basePriority;
        public uint handleCount;
        public uint threadCount;
        public uint userObjects;
        public uint gdiObjects;
        public ulong readOperationCount;
        public ulong writeOperationCount;
        public ulong otherOperationCount;
        public ulong readTransferCount;
        public ulong writeTransferCount;
        public ulong otherTransferCount;
        public bool elevated;
        public double cpuPercent;
        public uint operatingSystemContext;
        public uint platform;
        public double cyclePercent;
        public ushort uacVirtualization;
        public ushort dataExecutionPrevention;
        public bool isImmersive;
        public ushort intervalSeconds;
        public ushort deltaWorkingSetSize;
        public ushort deltaPageFaults;
        public bool hasChildWindow;
        public string processType;
        public string fileDescription;

        public SystemProcess(NativeMethods.SYSTEM_PROCESS_INFORMATION processInformation)
        {
            this.processId = (uint)processInformation.UniqueProcessId.ToInt32();
            this.name = Marshal.PtrToStringAuto(processInformation.ImageName.Buffer);
            this.cycleTime = processInformation.CycleTime;
            this.cpuTime = (ulong)(processInformation.KernelTime + processInformation.UserTime);
            this.sessionId = processInformation.SessionId;
            this.workingSetSize = (ulong)(processInformation.WorkingSetSize.ToInt64() / 1024);
            this.peakWorkingSetSize = (ulong)processInformation.PeakWorkingSetSize.ToInt64();
            this.privateWorkingSetSize = (ulong)processInformation.WorkingSetPrivateSize;
            this.sharedWorkingSetSize = (ulong)processInformation.WorkingSetSize.ToInt64() - this.privateWorkingSetSize;
            this.commitCharge = (ulong)processInformation.PrivatePageCount.ToInt64();
            this.pagedPool = (ulong)processInformation.QuotaPagedPoolUsage.ToInt64();
            this.nonPagedPool = (ulong)processInformation.QuotaNonPagedPoolUsage.ToInt64();
            this.pageFaults = processInformation.PageFaultCount;
            this.handleCount = processInformation.HandleCount;
            this.threadCount = processInformation.NumberOfThreads;
            this.readOperationCount = (ulong)processInformation.ReadOperationCount;
            this.writeOperationCount = (ulong)processInformation.WriteOperationCount;
            this.otherOperationCount = (ulong)processInformation.OtherOperationCount;
            this.readTransferCount = (ulong)processInformation.ReadTransferCount;
            this.writeTransferCount = (ulong)processInformation.WriteTransferCount;
            this.otherTransferCount = (ulong)processInformation.OtherTransferCount;
            this.processStatus = 0;

            if(processInformation.BasePriority <= 4)
            {
                this.basePriority = 0x00000040; //IDLE_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 6)
            {
                this.basePriority = 0x00004000; //BELOW_NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 8)
            {
                this.basePriority = 0x00000020; //NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 10)
            {
                this.basePriority = 0x00008000; //ABOVE_NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 13)
            {
                this.basePriority = 0x00000080; //HIGH_PRIORITY_CLASS
            }
            else
            {
                this.basePriority = 0x00000100; //REALTIME_PRIORITY_CLASS
            }
        }
    }

    public static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {
            internal uint NextEntryOffset;
            internal uint NumberOfThreads;
            internal long WorkingSetPrivateSize;
            internal uint HardFaultCount;
            internal uint NumberOfThreadsHighWatermark;
            internal ulong CycleTime;
            internal long CreateTime;
            internal long UserTime;
            internal long KernelTime;
            internal UNICODE_STRING ImageName;
            internal int BasePriority;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
            internal uint HandleCount;
            internal uint SessionId;
            internal IntPtr UniqueProcessKey;
            internal IntPtr PeakVirtualSize;
            internal IntPtr VirtualSize;
            internal uint PageFaultCount;
            internal IntPtr PeakWorkingSetSize;
            internal IntPtr WorkingSetSize;
            internal IntPtr QuotaPeakPagedPoolUsage;
            internal IntPtr QuotaPagedPoolUsage;
            internal IntPtr QuotaPeakNonPagedPoolUsage;
            internal IntPtr QuotaNonPagedPoolUsage;
            internal IntPtr PagefileUsage;
            internal IntPtr PeakPagefileUsage;
            internal IntPtr PrivatePageCount;
            internal long ReadOperationCount;
            internal long WriteOperationCount;
            internal long OtherOperationCount;
            internal long ReadTransferCount;
            internal long WriteTransferCount;
            internal long OtherTransferCount;
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenElevation = 20,
            TokenVirtualizationAllowed = 23,
            TokenVirtualizationEnabled = 24
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public Int32 TokenIsElevated;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UAC_ALLOWED
        {
            public Int32 UacAllowed;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UAC_ENABLED
        {
            public Int32 UacEnabled;
        }

        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags DesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool InheritHandle, int ProcessId);

        [System.Runtime.InteropServices.DllImport("advapi32", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess, UInt32 desiredAccess, out Microsoft.Win32.SafeHandles.SafeWaitHandle hToken);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(SafeWaitHandle hToken, TOKEN_INFORMATION_CLASS tokenInfoClass, IntPtr pTokenInfo, Int32 tokenInfoLength, out Int32 returnLength);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        internal const int SystemProcessInformation = 5;

        internal const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        internal const uint TOKEN_QUERY = 0x0008;
    }

    public static class Process
    {
        public static IEnumerable<SystemProcess> Enumerate()
        {
            List<SystemProcess> process = new List<SystemProcess>();

            int bufferSize = 1024;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            QuerySystemProcessInformation(ref buffer, ref bufferSize);

            long totalOffset = 0;

            while (true)
            {
                IntPtr currentPtr = (IntPtr)((long)buffer + totalOffset);

                NativeMethods.SYSTEM_PROCESS_INFORMATION pi = new NativeMethods.SYSTEM_PROCESS_INFORMATION();

                pi = (NativeMethods.SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(currentPtr, typeof(NativeMethods.SYSTEM_PROCESS_INFORMATION));

                process.Add(new SystemProcess(pi));

                if (pi.NextEntryOffset == 0)
                {
                    break;
                }

                totalOffset += pi.NextEntryOffset;
            }

            Marshal.FreeHGlobal(buffer);

            GetExtendedProcessInfo(process);

            return process;
        }

        private static void GetExtendedProcessInfo(List<SystemProcess> processes)
        {
            foreach(var process in processes)
            {
                IntPtr hProcess = GetProcessHandle(process);

                if(hProcess != IntPtr.Zero)
                {
                    try
                    {
                        process.elevated = IsElevated(hProcess);
                        process.userObjects = GetCountUserResources(hProcess);
                        process.gdiObjects = GetCountGdiResources(hProcess);
                        process.uacVirtualization = GetVirtualizationStatus(hProcess);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hProcess);
                    }
                }
            }
        }

        private static uint GetCountGdiResources(IntPtr hProcess)
        {
            return NativeMethods.GetGuiResources(hProcess, 0);
        }
        private static uint GetCountUserResources(IntPtr hProcess)
        {
            return NativeMethods.GetGuiResources(hProcess, 1);
        }

        private static ushort GetVirtualizationStatus(IntPtr hProcess)
        {
            /* Virtualization status:
             * 0: Unknown
             * 1: Disabled
             * 2: Enabled
             * 3: Not Allowed
             */
            ushort virtualizationStatus = 0;

            try
            {
                if(!IsVirtualizationAllowed(hProcess))
                {
                    virtualizationStatus = 3;
                }
                else
                {
                    if(IsVirtualizationEnabled(hProcess))
                    {
                        virtualizationStatus = 2;
                    }
                    else
                    {
                        virtualizationStatus = 1;
                    }
                }
            }
            catch(Win32Exception)
            {
            }

            return virtualizationStatus;
        }

        private static bool IsVirtualizationAllowed(IntPtr hProcess)
        {
            bool uacVirtualizationAllowed = false;

            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbUacAlowed = 0;
            IntPtr pUacAllowed = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbUacAlowed = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.UAC_ALLOWED));
                pUacAllowed = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbUacAlowed);

                if (pUacAllowed == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenVirtualizationAllowed, pUacAllowed, cbUacAlowed, out cbUacAlowed))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.UAC_ALLOWED uacAllowed = (NativeMethods.UAC_ALLOWED)System.Runtime.InteropServices.Marshal.PtrToStructure(pUacAllowed, typeof(NativeMethods.UAC_ALLOWED));

                uacVirtualizationAllowed = (uacAllowed.UacAllowed != 0);
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pUacAllowed != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pUacAllowed);
                    pUacAllowed = IntPtr.Zero;
                    cbUacAlowed = 0;
                }
            }

            return uacVirtualizationAllowed;
        }

        public static bool IsVirtualizationEnabled(IntPtr hProcess)
        {
            bool uacVirtualizationEnabled = false;

            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbUacEnabled = 0;
            IntPtr pUacEnabled = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbUacEnabled = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.UAC_ENABLED));
                pUacEnabled = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbUacEnabled);

                if (pUacEnabled == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenVirtualizationEnabled, pUacEnabled, cbUacEnabled, out cbUacEnabled))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.UAC_ENABLED uacEnabled = (NativeMethods.UAC_ENABLED)System.Runtime.InteropServices.Marshal.PtrToStructure(pUacEnabled, typeof(NativeMethods.UAC_ENABLED));

                uacVirtualizationEnabled = (uacEnabled.UacEnabled != 0);
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pUacEnabled != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pUacEnabled);
                    pUacEnabled = IntPtr.Zero;
                    cbUacEnabled = 0;
                }
            }

            return uacVirtualizationEnabled;
        }

        private static bool IsElevated(IntPtr hProcess)
        {
             bool fIsElevated = false;
            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbTokenElevation = 0;
            IntPtr pTokenElevation = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbTokenElevation = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.TOKEN_ELEVATION));
                pTokenElevation = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbTokenElevation);

                if (pTokenElevation == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, pTokenElevation, cbTokenElevation, out cbTokenElevation))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.TOKEN_ELEVATION elevation = (NativeMethods.TOKEN_ELEVATION)System.Runtime.InteropServices.Marshal.PtrToStructure(pTokenElevation, typeof(NativeMethods.TOKEN_ELEVATION));

                fIsElevated = (elevation.TokenIsElevated != 0);
            }
            catch (Win32Exception)
            {
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pTokenElevation != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pTokenElevation);
                    pTokenElevation = IntPtr.Zero;
                    cbTokenElevation = 0;
                }
            }

            return fIsElevated;
        }

        private static IntPtr GetProcessHandle(SystemProcess process)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, (int)process.processId);

            if(hProcess == IntPtr.Zero)
            {
                hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, (int)process.processId);
            }

            return hProcess;
        }

        private static void QuerySystemProcessInformation(ref IntPtr processInformationBuffer, ref int processInformationBufferSize)
        {
            const int maxTries = 10;
            bool success = false;

            for (int i = 0; i < maxTries; i++)
            {
                int sizeNeeded;

                int result = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemProcessInformation, processInformationBuffer, processInformationBufferSize, out sizeNeeded);

                if (result == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    if (processInformationBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(processInformationBuffer);
                    }

                    processInformationBuffer = Marshal.AllocHGlobal(sizeNeeded);
                    processInformationBufferSize = sizeNeeded;
                }

                else if (result < 0)
                {
                    throw new Exception(String.Format("NtQuerySystemInformation failed with code 0x{0:X8}", result));
                }

                else
                {
                    success = true;
                    break;
                }
            }

            if (!success)
            {
                throw new Exception("Failed to allocate enough memory for NtQuerySystemInformation");
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

    ############################################################################################################################

    # Helper functions.

    ############################################################################################################################

    function Get-ProcessListFromWmi {
        <#
        .Synopsis
            Name: Get-ProcessListFromWmi
            Description: Runs the WMI command to get Win32_Process objects and returns them in hashtable where key is processId.

        .Returns
            The list of processes in the form of hashtable.
        #>
        $processList = @{}

        $WmiProcessList = Get-WmiObject -Class Win32_Process

        foreach ($process in $WmiProcessList) {
            $processList.Add([int]$process.ProcessId, $process)
        }

        $processList
    }

    function Get-ProcessPerfListFromWmi {
        <#
        .Synopsis
            Name: Get-ProcessPerfListFromWmi
            Description: Runs the WMI command to get Win32_PerfFormattedData_PerfProc_Process objects and returns them in hashtable where key is processId.

        .Returns
            The list of processes performance data in the form of hashtable.
        #>
        $processPerfList = @{}

        $WmiProcessPerfList = Get-WmiObject -Class Win32_PerfFormattedData_PerfProc_Process

        foreach ($process in $WmiProcessPerfList) {
            try {
                $processPerfList.Add([int]$process.IdProcess, $process)
            }
            catch {
                if ($_.FullyQualifiedErrorId -eq 'ArgumentException') {
                    $processPerfList.Remove([int]$process.IdProcess)
                }

                $processPerfList.Add([int]$process.IdProcess, $process)
            }
        }

        $processPerfList
    }

    function Get-ProcessListFromPowerShell {
        <#
        .Synopsis
            Name: Get-ProcessListFromPowerShell
            Description: Runs the PowerShell command Get-Process to get process objects.

        .Returns
            The list of processes in the form of hashtable.
        #>
        $processList = @{}

        if ($psVersionTable.psversion.Major -ge 4) {
            #
            # It will crash to run 'Get-Process' with parameter 'IncludeUserName' multiple times in a session.
            # Currently the UI will not reuse the session as a workaround.
            # We need to remove the paramter 'IncludeUserName' if this issue happens again.
            #
            $PowerShellProcessList = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
        }
        else {
            $PowerShellProcessList = Get-Process -ErrorAction SilentlyContinue
        }

        foreach ($process in $PowerShellProcessList) {
            $processList.Add([int]$process.Id, $process)
        }

        $processList
    }

    function Get-LocalSystemAccount {
        <#
        .Synopsis
            Name: Get-LocalSystemAccount
            Description: Gets the name of local system account.

        .Returns
            The name local system account.
        #>
        $sidLocalSystemAccount = "S-1-5-18"

        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sidLocalSystemAccount)

        $objSID.Translate( [System.Security.Principal.NTAccount]).Value
    }

    function Get-NumberOfCores {
        <#
        .Synopsis
            Name: Get-NumberOfCores
            Description: Gets the number of cores on the system.

        .Returns
            The number of cores on the system.
        #>
        $processor = Get-WmiObject -Class Win32_Processor -Property NumberOfCores -ErrorAction Stop
        if ($processor) {
            $cores = $processor.NumberOfCores
            $cores
        }
        else {
            throw 'Unable to get processor information'
        }
    }


    ############################################################################################################################
    # Main script.
    ############################################################################################################################

    Add-Type -TypeDefinition $NativeProcessInfo
    Remove-Variable NativeProcessInfo

    try {
        #
        # Get the information about system processes from different sources.
        #
        $NumberOfCores = Get-NumberOfCores
        $NativeProcesses = [SMT.Process]::Enumerate()
        $WmiProcesses = Get-ProcessListFromWmi
        $WmiPerfProcesses = Get-ProcessPerfListFromWmi
        $PowerShellProcesses = Get-ProcessListFromPowerShell
        $LocalSystemAccount = Get-LocalSystemAccount

        $systemIdleProcess = $null
        $cpuInUse = 0

        # process paths and categorization taken from Task Manager
        # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
        $criticalProcesses = (
            "$($env:windir)\system32\winlogon.exe",
            "$($env:windir)\system32\wininit.exe",
            "$($env:windir)\system32\csrss.exe",
            "$($env:windir)\system32\lsass.exe",
            "$($env:windir)\system32\smss.exe",
            "$($env:windir)\system32\services.exe",
            "$($env:windir)\system32\taskeng.exe",
            "$($env:windir)\system32\taskhost.exe",
            "$($env:windir)\system32\dwm.exe",
            "$($env:windir)\system32\conhost.exe",
            "$($env:windir)\system32\svchost.exe",
            "$($env:windir)\system32\sihost.exe",
            "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:windir)\explorer.exe"
        )

        $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
        $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"

        $edgeProcesses = (
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
            "$($env:windir)\system32\browser_broker.exe"
        )

        #
        # Extract the additional process related information and fill up each nativeProcess object.
        #
        foreach ($nativeProcess in $NativeProcesses) {
            $WmiProcess = $null
            $WmiPerfProcess = $null
            $psProcess = $null

            # Same process as retrieved from WMI call Win32_Process
            if ($WmiProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
                $WmiProcess = $WmiProcesses.Get_Item([int]$nativeProcess.ProcessId)
            }

            # Same process as retrieved from WMI call Win32_PerfFormattedData_PerfProc_Process
            if ($WmiPerfProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
                $WmiPerfProcess = $WmiPerfProcesses.Get_Item([int]$nativeProcess.ProcessId)
            }

            # Same process as retrieved from PowerShell call Win32_Process
            if ($PowerShellProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
                $psProcess = $PowerShellProcesses.Get_Item([int]$nativeProcess.ProcessId)
            }

            if (($WmiProcess -eq $null) -or ($WmiPerfProcess -eq $null) -or ($psProcess -eq $null)) {continue}

            $nativeProcess.name = $WmiProcess.Name
            $nativeProcess.description = $WmiProcess.Description
            $nativeProcess.executablePath = $WmiProcess.ExecutablePath
            $nativeProcess.commandLine = $WmiProcess.CommandLine
            $nativeProcess.parentId = $WmiProcess.ParentProcessId

            #
            # Process CPU utilization and divide by number of cores
            # Win32_PerfFormattedData_PerfProc_Process PercentProcessorTime has a max number of 100 * cores so we want to normalize it
            #
            $nativeProcess.cpuPercent = $WmiPerfProcess.PercentProcessorTime / $NumberOfCores

            #
            # Process start time.
            #
            if ($WmiProcess.CreationDate) {
                $nativeProcess.CreationDateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($WmiProcess.CreationDate)
            }
            else {
                if ($nativeProcess.ProcessId -in @(0, 4)) {
                    # Under some circumstances, the process creation time is not available for processs "System Idle Process" or "System"
                    # In this case we assume that the process creation time is when the system was last booted.
                    $nativeProcess.CreationDateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject -Class win32_Operatingsystem).LastBootUpTime)
                }
            }

            #
            # Owner of the process.
            #
            if ($psVersionTable.psversion.Major -ge 4) {
                $nativeProcess.userName = $psProcess.UserName
            }

            # If UserName was not present available in results returned from Get-Process, then get the UserName from WMI class Get-Process
            <#
            ###### GetOwner is too slow so skip this part. ####

            if([string]::IsNullOrWhiteSpace($nativeProcess.userName))
            {
                $processOwner = Invoke-WmiMethod -InputObject $WmiProcess -Name GetOwner -ErrorAction SilentlyContinue

                try
                {
                    if($processOwner.Domain)
                    {
                        $nativeProcess.userName = "{0}\{1}" -f $processOwner.Domain, $processOwner.User
                    }
                    else
                    {
                        $nativeProcess.userName = "{0}" -f $processOwner.User
                    }
                }
                catch
                {
                }

                #In case of 'System Idle Process" and 'System' there is a need to explicitly mention NT Authority\System as Process Owner.
                if([string]::IsNullOrWhiteSpace($nativeProcess.userName) -and $nativeProcess.processId -in @(0, 4))
                {
                    $nativeProcess.userName = Get-LocalSystemAccount
                }
            }
            #>

            #In case of 'System Idle Process" and 'System' there is a need to explicitly mention NT Authority\System as Process Owner.
            if ([string]::IsNullOrWhiteSpace($nativeProcess.userName) -and $nativeProcess.processId -in @(0, 4)) {
                $nativeProcess.userName = $LocalSystemAccount
            }

            #
            # The process status ( i.e. running or suspended )
            #
            $countSuspendedThreads = @($psProcess.Threads | where { $_.WaitReason -eq [System.Diagnostics.ThreadWaitReason]::Suspended }).Count

            if ($psProcess.Threads.Count -eq $countSuspendedThreads) {
                $nativeProcess.ProcessStatus = 2
            }
            else {
                $nativeProcess.ProcessStatus = 1
            }

            # calculate system idle process
            if ($nativeProcess.processId -eq 0) {
                $systemIdleProcess = $nativeProcess
            }
            else {
                $cpuInUse += $nativeProcess.cpuPercent
            }


            if ($isLocal) {
                $nativeProcess.hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0

                if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                    $nativeProcess.fileDescription = $psProcess.MainModule.FileVersionInfo.FileDescription
                }

                if ($edgeProcesses -contains $nativeProcess.executablePath) {
                    # special handling for microsoft edge used by task manager
                    # group all edge processes into applications
                    $nativeProcess.fileDescription = 'Microsoft Edge'
                    $nativeProcess.processType = 'application'
                }
                elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                        -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
                    # process is windows if its executable path is a critical process, defined by Task Manager
                    # if the process has no executable path recorded, fallback to use the name to match to critical process
                    $nativeProcess.processType = 'windows'
                }
                elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
                    # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
                    $nativeProcess.processType = 'application'
                }
                else {
                    $nativeProcess.processType = 'background'
                }
            }
        }

        if ($systemIdleProcess -ne $null) {
            $systemIdleProcess.cpuPercent = [Math]::Max(100 - $cpuInUse, 0)
        }

    }
    catch {
        throw $_
    }
    finally {
        $WmiProcesses = $null
        $WmiPerfProcesses = $null
    }

    # Return the result to the caller of this script.
    $NativeProcesses
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUK+NgeZX0OG7fqdPRQrsQXeww
# AaKgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFKpJUjLOr+j/8o8U
# HCVH2Z04sCWjMA0GCSqGSIb3DQEBAQUABIIBAI8WPk+Qj4ikb8UuZy9F5QsgEqhp
# 1/5z2B8FD7jTTfaAhhp27zjI1ZShzTU2bUpn4Vt6hDW3sH5jQTKteHHeuIBH4q/p
# xVDk5a+mMvG2RsEMD8zii4nIh4ACN4iyfN6oFoce4NdjAYBoypi/kO8uJRrZzAsz
# umBTEUHxKregjYVhnfcxJB2phr6nNluAn3UeCAEuwUPpTLN9FUbuO3BkqE+dVNJT
# UJF8iyPPDOj+Z8rC0I8K/zIe/w6tJFHmX8EA7eH/Sm3O7nhzWt1JyfYMDZifUwat
# K0EPP7kqpjf7BDJ7SF2wW//WqhH2Eem9sD9sUbDiXMItvSKs70gMwzzjIgQ=
# SIG # End signature block
