<#
    
    .SYNOPSIS
        Sets the disk offline.
    
    .DESCRIPTION
        Sets the disk offline.

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
    
    .PARAMETER isOffline
        True to set the disk offline.

#>
function Set-StorageDiskOffline {
    param (
        [UInt32]
        $diskNumber,
        [Boolean]
        $isOffline = $true
    )
    
    Import-Module Storage
    
    Set-Disk -Number $diskNumber -IsOffline $isOffline
}