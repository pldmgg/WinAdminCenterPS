<#
    .SYNOPSIS
        Sets configuration of the specified network interface to use DHCP and updates DNS settings.
    
    .DESCRIPTION
        Sets configuration of the specified network interface to use DHCP and updates DNS settings.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
#>
function Set-DhcpIP {
    param (
        [Parameter(Mandatory = $rue)]
        [string] $interfaceIndex,

        [Parameter(Mandatory = $true)]
        [string] $addressFamily,

        [string] $preferredDNS,

        [string] $alternateDNS
    )
    
    Import-Module NetTCPIP
    
    $ErrorActionPreference = 'Stop'
    
    $ipInterface = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily
    $netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -ErrorAction SilentlyContinue
    if ($addressFamily -eq "IPv4") {
        $prefix = '0.0.0.0/0'
    }
    else {
        $prefix = '::/0'
    }
    
    $netRoute = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue
    
    # avoid extra work if dhcp already set up
    if ($ipInterface.Dhcp -eq 'Disabled') {
        if ($netIPAddress) {
            $netIPAddress | Remove-NetIPAddress -Confirm:$false
        }
        if ($netRoute) {
            $netRoute | Remove-NetRoute -Confirm:$false
        }
    
        $ipInterface | Set-NetIPInterface -DHCP Enabled
    }
    
    # reset or configure dns servers
    $interfaceAlias = $ipInterface.InterfaceAlias
    if ($preferredDNS) {
        netsh.exe interface $addressFamily set dnsservers name="$interfaceAlias" source=static validate=yes address="$preferredDNS"
        if (($LASTEXITCODE -eq 0) -and $alternateDNS) {
            netsh.exe interface $addressFamily add dnsservers name="$interfaceAlias" validate=yes address="$alternateDNS"
        }
    }
    else {
        netsh.exe interface $addressFamily delete dnsservers name="$interfaceAlias" address=all
    }
    
    # captures exit code of netsh.exe
    $LASTEXITCODE
    
}
    