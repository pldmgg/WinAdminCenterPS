<#
    
    .SYNOPSIS
        Get item's properties.
    
    .DESCRIPTION
        Get item's properties on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER Path
        String -- the path to the item whose properites are requested.
    
    .PARAMETER ItemType
        String -- What kind of item?
    
#>
function Get-ItemProperties {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $ItemType
    )
    
    Set-StrictMode -Version 5.0
    
    switch ($ItemType) {
        0 {
            Get-Volume $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
        }
        default {
            Get-ItemProperty $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
        }
    }
    
}