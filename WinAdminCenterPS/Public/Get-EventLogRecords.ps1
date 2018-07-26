<#
    
    .SYNOPSIS
        Get Log records of event channel by using Get-WinEvent cmdlet.
    
    .DESCRIPTION
        Get Log records of event channel by using Get-WinEvent cmdlet.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

#>
function Get-EventLogRecords {
    Param(
        [string]
        $filterXml,
        [bool]
        $reverseDirection
    )
    
    $ErrorActionPreference = 'SilentlyContinue'
    Import-Module Microsoft.PowerShell.Diagnostics;
    
    #
    # Prepare parameters for command Get-WinEvent
    #
    $winEventscmdParams = @{
        FilterXml = $filterXml;
        Oldest    = !$reverseDirection;
    }
    
    Get-WinEvent  @winEventscmdParams -ErrorAction SilentlyContinue | Select recordId,
    id, 
    @{Name = "Log"; Expression = {$_."logname"}}, 
    level, 
    timeCreated, 
    machineName, 
    @{Name = "Source"; Expression = {$_."ProviderName"}}, 
    @{Name = "Description"; Expression = {$_."Message"}}    
}