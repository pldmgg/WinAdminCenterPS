<#
    
    .SYNOPSIS
        Creates a new Quota for volume.
    
    .DESCRIPTION
        Creates a new Quota for volume.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER disabledQuota
        Enable or disable quota.
    
    .PARAMETER path
        Path of the quota.
    
    .PARAMETER size
        The size of quota.
    
    .PARAMETER softLimit
        Deny if usage exceeding quota limit.
    
#>
function New-StorageQuota {
    param
    (
        # Enable or disable quota.
        [Boolean]
        $disabledQuota,
    
        # Path of the quota.
        [String]
        $path,
    
        # The size of quota.
        [String]
        $size,
    
        # Deny if usage exceeding quota limit.
        [Boolean]
        $softLimit
    )
    
    Import-Module FileServerResourceManager
    
    $scriptArgs = @{
        Path = $path;
    }
    
    if ($size) {
        $scriptArgs.Size = $size
    }
    if ($disabledQuota) {
        $scriptArgs.Disabled = $true
    }
    if ($softLimit) {
        $scriptArgs.SoftLimit = $true
    }
    
    New-FsrmQuota @scriptArgs
}