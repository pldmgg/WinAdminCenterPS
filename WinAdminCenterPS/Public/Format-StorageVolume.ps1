<#
    
    .SYNOPSIS
        Formats a drive by drive letter.
    
    .DESCRIPTION
        Formats a drive by drive letter.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER driveLetter
        The drive letter.
    
    .PARAMETER allocationUnitSizeInBytes
        The allocation unit size.
    
    .PARAMETER fileSystem
        The file system type.
    
    .PARAMETER fileSystemLabel
        The file system label.    
    
    .PARAMETER compress
        True to compress, false otherwise.
    
    .PARAMETER quickFormat
        True to run a quick format.
#>
function Format-StorageVolume {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $driveLetter,
    
        [UInt32]
        $allocationUnitSizeInBytes,
    
        [String]
        $fileSystem,
    
        [String]
        $newFileSystemLabel,
    
        [Boolean]
        $compress = $false,
    
        [Boolean]
        $quickFormat = $true
    )
    
    Import-Module Storage
    
    #
    # Prepare parameters for command Format-Volume
    #
    $FormatVolumecmdParams = @{
        DriveLetter = $driveLetter;
        Compress = $compress;
        Full = -not $quickFormat}
    
    if($allocationUnitSizeInBytes -ne 0)
    {
        $FormatVolumecmdParams.AllocationUnitSize = $allocationUnitSizeInBytes
    }
    
    if ($fileSystem)
    {
        $FormatVolumecmdParams.FileSystem = $fileSystem
    }
    
    if ($newFileSystemLabel)
    {
        $FormatVolumecmdParams.NewFileSystemLabel = $newFileSystemLabel
    }
    
    Format-Volume @FormatVolumecmdParams -confirm:$false
    
}