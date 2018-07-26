<#
    
    .SYNOPSIS
        Edit a new firewall rule in the system.
    
    .DESCRIPTION
        Edit a new firewall rule in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Edit-FirewallRule {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $instanceId,
    
        [Parameter(Mandatory = $false)]
        [String]
        $displayName,
    
        [Parameter(Mandatory = $false)]
        [int]
        $action,
    
        [Parameter(Mandatory = $false)]
        [String]
        $description,
    
        [Parameter(Mandatory = $false)]
        [int]
        $direction,
    
        [Parameter(Mandatory = $false)]
        [bool]
        $enabled,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $icmpType,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $localPort,
    
        [Parameter(Mandatory = $false)]
        [String]
        $profile,
    
        [Parameter(Mandatory = $false)]
        [String]
        $protocol,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $remotePort
    )
    
    Import-Module netsecurity
    
    $command = 'Set-NetFirewallRule -Name $instanceId'
    if ($displayName) {
        $command += ' -NewDisplayName $displayName';
    }
    if ($action) {
        $command += ' -Action ' + $action;
    }
    if ($description) {
        $command += ' -Description $description';
    }
    if ($direction) {
        $command += ' -Direction ' + $direction;
    }
    if ($PSBoundParameters.ContainsKey('enabled')) {
        $command += ' -Enabled ' + $enabled;
    }
    if ($icmpType) {
        $command += ' -IcmpType $icmpType';
    }
    if ($localPort) {
        $command += ' -LocalPort $localPort';
    }
    if ($profile) {
        $command += ' -Profile $profile';
    }
    if ($protocol) {
        $command += ' -Protocol $protocol';
    }
    if ($remotePort) {
        $command += ' -RemotePort $remotePort';
    }
    
    Invoke-Expression $command
}