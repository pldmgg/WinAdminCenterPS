<#
    
    .SYNOPSIS
        Set local group properties.
    
    .DESCRIPTION
        Set local group properties. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-LocalGroupProperties {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $GroupName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Description
    )
    
    try {
        $group = [ADSI]("WinNT://localhost/$GroupName, group")
        if ($Description -ne $null) { $group.Description = $Description }
        $group.SetInfo()
    }
    catch [System.Management.Automation.RuntimeException]
    {
            Write-Error $_.Exception.Message
    }
    
    return $true
    
}