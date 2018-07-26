<#
    
    .SYNOPSIS
        Gets status of the connection to the server.
    
    .DESCRIPTION
        Gets status of the connection to the server.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ServerConnectionStatus {
    import-module CimCmdlets
    
    $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    $Caption = $OperatingSystem.Caption
    $ProductType = $OperatingSystem.ProductType
    $Version = $OperatingSystem.Version
    $Status = @{ Label = $null; Type = 0; Details = $null; }
    $Result = @{ Status = $Status; Caption = $Caption; ProductType = $ProductType; Version = $Version; }
    if ($Version -and ($ProductType -eq 2 -or $ProductType -eq 3)) {
        $V = [version]$Version
        $V2016 = [version]'10.0'
        $V2012 = [version]'6.2'
        $V2008r2 = [version]'6.1'
        
        if ($V -ge $V2016) {
            return $Result;
        } 
        
        if ($V -ge $V2008r2) {
            $Key = 'HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine'
            $WmfStatus = $false;
            $Exists = Get-ItemProperty -Path $Key -Name PowerShellVersion -ErrorAction SilentlyContinue
            if ($Exists -and ($Exists.Length -ne 0)) {
                $WmfVersionInstalled = $exists.PowerShellVersion
                if ($WmfVersionInstalled.StartsWith('5.')) {
                    $WmfStatus = $true;
                }
            }
    
            if (!$WmfStatus) {            
                $status.Label = 'wmfMissing-label'
                $status.Type = 3
                $status.Details = 'wmfMissing-details'
            }
    
            return $result;
        }
    }
    
    $status.Label = 'unsupported-label'
    $status.Type = 3
    $status.Details = 'unsupported-details'
    return $result;
    
}