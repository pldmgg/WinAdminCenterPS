<#
    
    .SYNOPSIS
        Checks if a file or folder exists
    
    .DESCRIPTION
        Checks if a file or folder exists
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
    Administrators
    
    .PARAMETER Path
        String -- The path to check if it exists
    
#>
function Test-FileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path    
    )
    
    Set-StrictMode -Version 5.0
    
    Test-Path -path $Path
    
}