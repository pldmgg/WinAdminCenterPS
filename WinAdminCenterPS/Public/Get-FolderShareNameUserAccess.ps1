<#
    
    .SYNOPSIS
        Gets user access rights to a folder share
    
    .DESCRIPTION
        Gets user access rights to a folder share
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .ROLE
        Administrators

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER Name
        String -- Name of the share.
    
    .PARAMETER AccountName
        String -- The user identification (AD / Local user).
    
    .PARAMETER AccessRight
        String -- Access rights of the user.
    
#>
function Get-FolderShareNameUserAccess {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,
    
        [Parameter(Mandatory = $true)]
        [String]
        $AccountName
    )
    
    Set-StrictMode -Version 5.0
    
    Get-SmbShareAccess -Name "$Name" | Select-Object AccountName, AccessControlType, AccessRight | Where-Object {$_.AccountName -eq "$AccountName"}    
}