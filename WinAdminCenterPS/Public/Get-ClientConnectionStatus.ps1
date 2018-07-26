<#
    
    .SYNOPSIS
        Gets status of the connection to the client computer.
    
    .DESCRIPTION
        Gets status of the connection to the client computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ClientConnectionStatus {
    import-module CimCmdlets
    $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    $Caption = $OperatingSystem.Caption
    $ProductType = $OperatingSystem.ProductType
    $Version = $OperatingSystem.Version
    $Status = @{ Label = $null; Type = 0; Details = $null; }
    $Result = @{ Status = $Status; Caption = $Caption; ProductType = $ProductType; Version = $Version; }
    
    if ($Version -and $ProductType -eq 1) {
        $V = [version]$Version
        $V10 = [version]'10.0'
        if ($V -ge $V10) {
            return $Result;
        } 
    }
    
    $Status.Label = 'unsupported-label'
    $Status.Type = 3
    $Status.Details = 'unsupported-details'
    return $Result;
    
}