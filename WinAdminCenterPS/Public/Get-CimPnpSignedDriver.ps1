<#
    
    .SYNOPSIS
        Get Pnp signed driver by using CIM provider.
    
    .DESCRIPTION
        Get Pnp signed driver by using CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimPnpSignedDriver {
    Param(
    [string]$DeviceId
    )
    
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -Query "select * from Win32_PnPSignedDriver where DeviceID='$DeviceId'"    
}