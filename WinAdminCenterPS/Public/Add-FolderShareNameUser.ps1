<#
    
    .SYNOPSIS
        Adds a user to the folder share.
    
    .DESCRIPTION
        Adds a user to the folder share.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Name
        String -- Name of the share.
    
    .PARAMETER AccountName
        String -- The user identification (AD / Local user).
    
    .PARAMETER AccessRight
        String -- Access rights of the user.
    
#>
function Add-FolderShareNameUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,
    
        [Parameter(Mandatory = $true)]
        [String]
        $AccountName,
    
        [Parameter(Mandatory = $true)]
        [String]
        $AccessRight
    )
    
    Set-StrictMode -Version 5.0
    
    Grant-SmbShareAccess -Name "$Name" -AccountName "$AccountName" -AccessRight "$AccessRight" -Force    
}