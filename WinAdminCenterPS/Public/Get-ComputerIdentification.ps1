<#
    
    .SYNOPSIS
        Gets the local computer domain/workplace information.
    
    .DESCRIPTION
        Gets the local computer domain/workplace information.
        Returns the computer identification information.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ComputerIdentification {
    import-module CimCmdlets
    
    $ComputerSystem = Get-CimInstance -Class Win32_ComputerSystem;
    $ComputerName = $ComputerSystem.DNSHostName
    if ($ComputerName -eq $null) {
        $ComputerName = $ComputerSystem.Name
    }
    
    $fqdn = ([System.Net.Dns]::GetHostByName($ComputerName)).HostName
    
    $ComputerSystem | Microsoft.PowerShell.Utility\Select-Object `
    @{ Name = "ComputerName"; Expression = { $ComputerName }},
    @{ Name = "Domain"; Expression = { if ($_.PartOfDomain) { $_.Domain } else { $null } }},
    @{ Name = "DomainJoined"; Expression = { $_.PartOfDomain }},
    @{ Name = "FullComputerName"; Expression = { $fqdn }},
    @{ Name = "Workgroup"; Expression = { if ($_.PartOfDomain) { $null } else { $_.Workgroup } }}    
}