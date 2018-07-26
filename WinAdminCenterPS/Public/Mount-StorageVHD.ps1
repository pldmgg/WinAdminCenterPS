<#
    
    .SYNOPSIS
        Attaches a VHD as disk.
    
    .DESCRIPTION
        Attaches a VHD as disk.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER path
        The VHD path
    
#>
function Mount-StorageVHD {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $path
    )
    
    Import-Module Storage
    
    Mount-DiskImage -ImagePath $path
}