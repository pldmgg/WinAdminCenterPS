<#
    
    .SYNOPSIS
        Sets configuration of the specified network interface to use a static IP address and updates DNS settings.
    
    .DESCRIPTION
        Sets configuration of the specified network interface to use a static IP address and updates DNS settings. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators
    
#>
function Set-StaticIP {
    param (
        [Parameter(Mandatory = $true)] [string] $interfaceIndex,
        [Parameter(Mandatory = $true)] [string] $ipAddress,
        [Parameter(Mandatory = $true)] [string] $prefixLength,
        [string] $defaultGateway,
        [string] $preferredDNS,
        [string] $alternateDNS,
        [Parameter(Mandatory = $true)] [string] $addressFamily
    )
    
    Import-Module NetTCPIP
    
    Set-StrictMode -Version 5.0
    $ErrorActionPreference = 'Stop'
    
    $netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -ErrorAction SilentlyContinue
    
    if ($addressFamily -eq "IPv4") {
        $prefix = '0.0.0.0/0'
    }
    else {
        $prefix = '::/0'
    }
    
    $netRoute = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue
    
    if ($netIPAddress) {
        $netIPAddress | Remove-NetIPAddress -Confirm:$false
    }
    if ($netRoute) {
        $netRoute | Remove-NetRoute -Confirm:$false
    }
    
    Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -DHCP Disabled
    
    try {
        # this will fail if input is invalid
        if ($defaultGateway) {
            $netIPAddress | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $defaultGateway -AddressFamily $addressFamily -ErrorAction Stop
        }
        else {
            $netIPAddress | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -AddressFamily $addressFamily -ErrorAction Stop
        }
    }
    catch {
        # restore net route and ip address to previous values
        if ($netRoute -and $netIPAddress) {
            $netIPAddress | New-NetIPAddress -DefaultGateway $netRoute.NextHop -PrefixLength $netIPAddress.PrefixLength
        }
        elseif ($netIPAddress) {
            $netIPAddress | New-NetIPAddress
        }
        throw
    }
    
    $interfaceAlias = $netIPAddress.InterfaceAlias
    if ($preferredDNS) {
        netsh.exe interface $addressFamily set dnsservers name="$interfaceAlias" source=static validate=yes address="$preferredDNS"
        if (($LASTEXITCODE -eq 0) -and $alternateDNS) {
            netsh.exe interface $addressFamily add dnsservers name="$interfaceAlias" validate=yes address="$alternateDNS"
        }
        return $LASTEXITCODE
    }
    else {
        return 0
    }    
}
    