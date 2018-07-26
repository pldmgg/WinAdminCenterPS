<#
    
    .SYNOPSIS
        Stop the process on a computer.
    
    .DESCRIPTION
        Stop the process on a computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-Processes {
    param
    (
        [Parameter(Mandatory = $true)]
        [int[]]
        $processIds
    )
    
    Set-StrictMode -Version 5.0
    
    Stop-Process $processIds -Force
}