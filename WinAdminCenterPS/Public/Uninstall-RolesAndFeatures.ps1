<#
    .SYNOPSIS
        UnInstalls a Feature/Role/Role Service on the target server.
    
    .DESCRIPTION
        UnInstalls a Feature/Role/Role Service on the target server, using UnInstall-WindowsFeature PowerShell cmdlet.
        Returns a status object that contains the following properties:
            success - true/false depending on if the overall operation Succeeded
            status - status message
            result - response from UnInstall-WindowsFeature call

        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER FeatureName
        Is a required parameter and is the name of the Role/Feature/Role Service to un-install
    
    .PARAMETER IncludeManagementTools
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .PARAMETER Restart
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .EXAMPLE
        # Un-Installs the feature 'ManagementObject'
        Uninstall-RolesAndFeatures -FeatureName 'ManagementOData'
    
    
    .EXAMPLE
        # Un-Installs the role 'Web-Server' and management tools
        Uninstall-RolesAndFeatures -FeatureName 'Web-Server' -IncludeManagementTools
    
    .EXAMPLE
        # Un-Installs the feature 'ManagementObject' without management tools and reboots the server
        Uninstall-RolesAndFeatures -FeatureName 'ManagementOData' -Restart
    
    .ROLE
        Administrators
    
#>
function Uninstall-RolesAndFeatures {
    param(
        [Parameter(Mandatory=$True)]
        [string[]]
        $FeatureName,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $IncludeManagementTools,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $Restart,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $WhatIf
    )
    
    Import-Module ServerManager
    
    Enum UnInstallStatus {
        Failed = 0
        Succeeded = 1
        NoSuchFeature = 2
        NotInstalled = 3
        Pending = 4
    }
    
    $result  = $Null
    $status = $Null
    $success = $False
    
    $ErrorActionPreference = "Stop"
    
    $feature = Get-WindowsFeature -Name $FeatureName
    If ($feature) {
        If ($feature.Where({$_.InstallState -eq 'Installed'})) {
            Try {
                $result = UnInstall-WindowsFeature -Name $FeatureName -IncludeManagementTools:$IncludeManagementTools -Restart:$Restart -WhatIf:$WhatIf
                $success = $result -AND $result.Success
                $status = if ($success) { [UnInstallStatus]::Succeeded } Else { [UnInstallStatus]::Failed }
            }
            Catch {
                If ($success -AND $Restart -AND $result.restartNeeded -eq 'Yes') {
                    $status = [UnInstallStatus]::Pending
                    $error.clear()
                } Else {
                    Throw
                }
            }
        } Else {
            $success = $True
            $status = [UnInstallStatus]::NotInstalled
        }
    } Else {
        $success = $False
        $status = [UnInstallStatus]::NoSuchFeature
    }
    
    @{ 'success' = $success ; 'status' = $status ; 'result' = $result }
    
}