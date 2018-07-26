<#
    .SYNOPSIS
        Detaches the VHD.
    
    .DESCRIPTION
        Detaches the VHD.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER location
        The disk location
    
#>
function Dismount-StorageVHD {
    param (
        [parameter(Mandatory=$true)]
        [String]
        $location
    )
    
    Import-Module Storage
    
    Dismount-DiskImage -ImagePath $location
}