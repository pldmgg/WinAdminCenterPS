<#

    .SYNOPSIS
        Creates the mini dump of the process on downlevel computer.

    .DESCRIPTION
        Creates the mini dump of the process on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function New-ProcessDumpDownlevel {
    param
    (
        # The process ID of the process whose mini dump is supposed to be created.
        [int]
        $processId,

        # Path to the process dump file name.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $fileName
    )

    $NativeCode = @"

namespace SME
{
    using System;
    using System.Runtime.InteropServices;

    public static class ProcessMiniDump
    {
        private enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000
        };

        [DllImport("dbghelp.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private extern static bool MiniDumpWriteDump(
            System.IntPtr hProcess,
            int processId,
            Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
            MINIDUMP_TYPE dumpType,
            System.IntPtr exceptionParam,
            System.IntPtr userStreamParam,
            System.IntPtr callbackParam);

        public static void Create(int processId, string fileName)
        {
            if(string.IsNullOrWhiteSpace(fileName))
            {
                throw new ArgumentNullException(fileName);
            }

            if(processId < 0)
            {
                throw new ArgumentException("Incorrect value of ProcessId", "processId");
            }

            System.IO.FileStream fileStream = null;

            try
            {
                fileStream = System.IO.File.OpenWrite(fileName);

                bool sucess = MiniDumpWriteDump(
                    System.Diagnostics.Process.GetCurrentProcess().Handle,
                    processId,
                    fileStream.SafeFileHandle,
                    MINIDUMP_TYPE.MiniDumpWithFullMemory | MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo | MINIDUMP_TYPE.MiniDumpWithHandleData | MINIDUMP_TYPE.MiniDumpWithUnloadedModules | MINIDUMP_TYPE.MiniDumpWithThreadInfo,
                    System.IntPtr.Zero,
                    System.IntPtr.Zero,
                    System.IntPtr.Zero);

                if (!sucess)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
            }
            finally
            {
                if(fileStream != null)
                {
                    fileStream.Close();
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

    ############################################################################################################################

    # Main script.

    ############################################################################################################################

    Add-Type -TypeDefinition $NativeCode
    Remove-Variable NativeCode

    $fileName = "$($env:temp)\$($fileName)"

    try {
        # Create the mini dump using native call.
        try {
            [SME.ProcessMiniDump]::Create($processId, $fileName)
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'DumpFilePath' -Value $fileName
            $result
        }
        catch {
            if ($_.FullyQualifiedErrorId -eq "ArgumentException") {
                throw "Unable to create the mini dump of the process. Please make sure that the processId is correct and the user has required permissions to create the mini dump of the process."
            }
            elseif ($_.FullyQualifiedErrorId -eq "UnauthorizedAccessException") {
                throw "Access is denied. User does not relevant permissions to create the mini dump of process with ID: {0}" -f $processId
            }
            else {
                throw
            }
        }
    }
    finally {
        if (Test-Path $fileName) {
            if ((Get-Item $fileName).length -eq 0) {
                # Delete the zero byte file.
                Remove-Item -Path $fileName -Force -ErrorAction Stop
            }
        }
    }
}
