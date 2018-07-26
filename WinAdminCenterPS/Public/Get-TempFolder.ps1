<#
    
    .SYNOPSIS
        Script that gets temp folder based on the target node.
    
    .DESCRIPTION
        Script that gets temp folder based on the target node.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-TempFolder {
    #Get-ChildItem env: | where {$_.name -contains "temp"}
    Get-Childitem -Path Env:* | where-Object {$_.Name -eq "TEMP"}
}