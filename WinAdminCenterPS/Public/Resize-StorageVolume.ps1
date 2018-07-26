<#
    
    .SYNOPSIS
        Resizes the volume.
    
    .DESCRIPTION
        Resizes the volume.

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
    
    .PARAMETER newSize
        The new size.
    
#> 
function Resize-StorageVolume {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $driveLetter,
    
        [UInt64]
        $newSize
    
    )
    
    Import-Module Storage
    
    Resize-Partition -DriveLetter $driveLetter -Size $newSize
}