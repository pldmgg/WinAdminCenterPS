<#
    
    .SYNOPSIS
        Creates a volume.
    
    .DESCRIPTION
        Creates a volume.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER diskNumber
        The disk number.
    
    .PARAMETER driveLetter
        The drive letter.
    
    .PARAMETER sizeInBytes
        The size in bytes.
    
    .PARAMETER fileSystem
        The file system.
    
    .PARAMETER allocationUnitSizeInBytes
        The allocation unit size.
    
    .PARAMETER fileSystemLabel
        The file system label.
    
    .PARAMETER useMaxSize
        True to use the maximum size.
    
#>
function New-StorageVolume {
    param (
        [parameter(Mandatory=$true)]
        [String]
        $diskNumber,
        [parameter(Mandatory=$true)]
        [Char]
        $driveLetter,
        [uint64]
        $sizeInBytes,
        [parameter(Mandatory=$true)]
        [string]
        $fileSystem,
        [parameter(Mandatory=$true)]
        [uint32]
        $allocationUnitSizeInBytes,
        [string]
        $fileSystemLabel,
        [boolean]
        $useMaxSize = $false
    )
    
    Import-Module Microsoft.PowerShell.Management
    Import-Module Microsoft.PowerShell.Utility
    Import-Module Storage
    
    # This is a work around for getting rid of format dialog on the machine when format fails for reasons. Get rid of this code once we make changes on the UI to identify correct combinations.
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='ShellHWDetection'" -ErrorAction SilentlyContinue | out-null
    if($service) 
    {
        $service.StopService();
    }
    
    
    if ($useMaxSize)
    {
        $p = New-Partition -DiskNumber $diskNumber -DriveLetter $driveLetter -UseMaximumSize
    } 
    else
    {
        $p = New-Partition -DiskNumber $diskNumber -DriveLetter $driveLetter -Size $sizeInBytes
    }
    
    # Format only when partition is created
    if ($p)
    {
        Format-Volume -DriveLetter $driveLetter -FileSystem $fileSystem -NewFileSystemLabel "$fileSystemLabel" -AllocationUnitSize $allocationUnitSizeInBytes -confirm:$false
        # TODO: Catch exception that occur with race condition. We don't have specific exception details as unable to repro. 
        # For now surface any exception that occur here to the UI.
    }
    
    if($service) 
    {
        $service.StartService();
    }
    
    $volume = Get-Volume -DriveLetter $driveLetter
    
    if ($volume.FileSystemLabel) { 
        $volumeName = $volume.FileSystemLabel + " (" + $volume.DriveLetter + ":)"
    } else { 
        $volumeName = "(" + $volume.DriveLetter + ":)"
    }
    
    return @{ 
        Name = $volumeName;
        HealthStatus = $volume.HealthStatus;
        DriveType = $volume.DriveType;
        DriveLetter = $volume.DriveLetter;
        FileSystem = $volume.FileSystem;
        FileSystemLabel = $volume.FileSystemLabel;
        Path = $volume.Path;
        Size = $volume.Size;
        SizeRemaining = $volume.SizeRemaining;
    }
}