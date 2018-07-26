<#
    
    .SYNOPSIS
        Script that set windows update automatic update options in registry key.
    
    .DESCRIPTION
        Script that set windows update automatic update options in registry key.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .EXAMPLE
        Set AUoptions
        PS C:\> Set-AUoptions "2"
    
    .ROLE
        Administrators
    
#>
function Set-AutomaticUpdatesOptions {
    Param(
    [Parameter(Mandatory = $true)]
    [string]$AUOptions
    )
    
    $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    switch($AUOptions)
    {
        '0' # Not defined, delete registry folder if exist
            {
                if (Test-Path $Path) {
                    Remove-Item $Path
                }
            }
        '1' # Disabled, set NoAutoUpdate to 1 and delete AUOptions if existed
            {
                if (Test-Path $Path) {
                    Set-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x1 -Force
                    Remove-ItemProperty -Path $Path -Name AUOptions
                }
                else {
                    New-Item $Path -Force
                    New-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x1 -Force
                }
            }
        default # else 2-5, set AUoptions
            {
                 if (!(Test-Path $Path)) {
                     New-Item $Path -Force
                }
                Set-ItemProperty -Path $Path -Name AUOptions -Value $AUOptions -Force
                Set-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x0 -Force
            }
    }
    
}