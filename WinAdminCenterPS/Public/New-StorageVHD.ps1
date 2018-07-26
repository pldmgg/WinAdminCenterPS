<#

    .SYNOPSIS
        Creates a new VHD.

    .DESCRIPTION
        Creates a new VHD.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
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