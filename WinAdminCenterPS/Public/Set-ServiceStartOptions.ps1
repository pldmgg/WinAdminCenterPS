<#
    
    .SYNOPSIS
        Sets the startup type, path and parameters for the specified service.
    
    .DESCRIPTION
        Sets the startup type, path and parameters for the specified service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ServiceStartOptions {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName,
        [string] $path,
        [string] $startupType
    )
    
    
    if ($startupType) {
        $service = Get-WmiObject -class Win32_Service -namespace root\cimv2 | Where-Object { $_.Name -eq $serviceName }
        if ($service) {
            $startupResult = $service.ChangeStartMode($startupType)
            if ($startupResult -and $startupResult.ReturnValue -ne 0) {
                return $startupResult.ReturnValue
            }
        }
        else {
            # unexpected error
            return -1
        }
    }
    
    if ($path) {
        $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
        Set-ItemProperty -Path $regPath -Name ImagePath -Value $path
    }
    
    # if we get here the script was successful, return 0 for success
    return 0
    
}