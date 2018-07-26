<#
    
    .SYNOPSIS
        Gets a Microsoft.Sme.PowerShell endpoint configuration.
    
    .DESCRIPTION
        Gets a Microsoft.Sme.PowerShell endpoint configuration.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-RbacSessionConfiguration {
    param(
        [Parameter(Mandatory = $false)]
        [String]
        $configurationName = "Microsoft.Sme.PowerShell"
    )
    
    ## check if it's full administrators
    if ((Get-Command Get-PSSessionConfiguration -ErrorAction SilentlyContinue) -ne $null) {
        @{
            Administrators = $true
            Configured = (Get-PSSessionConfiguration $configurationName -ErrorAction SilentlyContinue) -ne $null
        }
    } else {
        @{
            Administrators = $false
            Configured = $false
        }
    }
}