<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host Live Migration settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host Live Migration settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVHostLiveMigrationSettings {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $virtualMachineMigrationEnabled,
        [Parameter(Mandatory = $true)]
        [int]
        $maximumVirtualMachineMigrations,
        [Parameter(Mandatory = $true)]
        [int]
        $virtualMachineMigrationPerformanceOption,
        [Parameter(Mandatory = $true)]
        [int]
        $virtualMachineMigrationAuthenticationType
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    if ($virtualMachineMigrationEnabled) {
        $isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2;
        
        Enable-VMMigration;
    
        # Create arguments
        $args = @{'MaximumVirtualMachineMigrations' = $maximumVirtualMachineMigrations};
        $args += @{'VirtualMachineMigrationAuthenticationType' = $virtualMachineMigrationAuthenticationType; };
    
        if (!$isServer2012) {
            $args += @{'VirtualMachineMigrationPerformanceOption' = $virtualMachineMigrationPerformanceOption; };
        }
    
        Set-VMHost @args;
    } else {
        Disable-VMMigration;
    }
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        maximumVirtualMachineMigrations, `
        VirtualMachineMigrationAuthenticationType, `
        VirtualMachineMigrationEnabled, `
        VirtualMachineMigrationPerformanceOption
    
}