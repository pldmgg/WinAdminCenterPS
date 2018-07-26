<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host Physical GPU settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host Physical GPU settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVHostPhysicalGpuSettings {
    Set-StrictMode -Version 5.0
    Import-Module CimCmdlets
    
    Get-CimInstance -Namespace "root\virtualization\v2" -Class "Msvm_Physical3dGraphicsProcessor" | `
        Microsoft.PowerShell.Utility\Select-Object EnabledForVirtualization, `
        Name, `
        DriverDate, `
        DriverInstalled, `
        DriverModelVersion, `
        DriverProvider, `
        DriverVersion, `
        DirectXVersion, `
        PixelShaderVersion, `
        DedicatedVideoMemory, `
        DedicatedSystemMemory, `
        SharedSystemMemory, `
        TotalVideoMemory
    
}