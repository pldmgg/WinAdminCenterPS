<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host Enhanced Session Mode settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host Enhanced Session Mode settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVEnhancedSessionModeSettings {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $enableEnhancedSessionMode
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    # Create arguments
    $args = @{'EnableEnhancedSessionMode' = $enableEnhancedSessionMode};
    
    Set-VMHost @args
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        EnableEnhancedSessionMode
    
}