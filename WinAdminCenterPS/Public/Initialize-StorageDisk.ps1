<#
    
    .SYNOPSIS
        Initializes a disk
    
    .DESCRIPTION
        Initializes a disk

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER diskNumber
        The disk number
    
    .PARAMETER partitionStyle
        The partition style
    
#>
function Initialize-StorageDisk {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $diskNumber,
    
        [Parameter(Mandatory = $true)]
        [String]
        $partitionStyle
    )
    
    Import-Module Storage
    
    Initialize-Disk -Number $diskNumber -PartitionStyle $partitionStyle
}