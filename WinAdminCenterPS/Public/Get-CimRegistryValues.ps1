<#
    
    .SYNOPSIS
        Gets Registry Values on a registry key.
    
    .DESCRIPTION
        Gets Registry Values on a registry key.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimRegistryValues {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/microsoft/windows/managementtools -ClassName MSFT_MTRegistryKey -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName GetValues
    
}