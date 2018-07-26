<#
    
    .SYNOPSIS
        Script that get windows update automatic update options from registry key.
    
    .DESCRIPTION
        Script that get windows update automatic update options from registry key.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-AutomaticUpdatesOptions {
    Import-Module Microsoft.PowerShell.Management
    
    # If there is AUOptions, return it, otherwise return NoAutoUpdate value
    $option = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorVariable myerror -ErrorAction SilentlyContinue).AUOptions
    if ($myerror) {
        $option = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorVariable myerror  -ErrorAction SilentlyContinue).NoAutoUpdate
        if ($myerror) {
            $option = 0 # not defined
        }
    }
    return $option
}