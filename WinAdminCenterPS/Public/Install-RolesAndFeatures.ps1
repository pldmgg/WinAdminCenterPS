<#
    
    .SYNOPSIS
        Installs a Feature/Role/Role Service on the target server.
    
    .DESCRIPTION
        Installs a Feature/Role/Role Service on the target server, using Install-WindowsFeature PowerShell cmdlet.
        Returns a status object that contains the following properties:
            success - true/false depending on if the overall operation Succeeded
            status - status message
            result - response from Install-WindowsFeature call

        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER FeatureName
        Is a required parameter and is the name of the Role/Feature/Role Service to install
    
    .PARAMETER IncludeAllSubFeature
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .PARAMETER IncludeManagementTools
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .PARAMETER Restart
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .EXAMPLE
        # Installs the feature 'ManagementObject' without subfeature and management tools
        Install-RolesAndFeatures -FeatureName 'ManagementOData'
        
    .EXAMPLE
        # Installs the role 'Web-Server' with all dependencies and management tools
        Install-RolesAndFeatures -FeatureName 'Web-Server' -IncludeAllSubFeature -IncludeManagementTools
    
    
    .EXAMPLE
        # Installs the feature 'ManagementObject' without subfeature and management tools and reboots the server
        Install-RolesAndFeatures -FeatureName 'ManagementOData' -Restart
    
    .ROLE
        Administrators
    
#>
function Install-RolesAndFeatures {    
    param(
        [Parameter(Mandatory=$True)]
        [string[]]
        $FeatureName,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $IncludeAllSubFeature,
    
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
    
    Enum InstallStatus {
        Failed = 0
        Succeeded = 1
        NoSuchFeature = 2
        AlreadyInstalled = 3
        Pending = 4
    }
    
    $result  = $Null
    $status = $Null
    $success = $False
    
    $ErrorActionPreference = "Stop"
    
    $feature = Get-WindowsFeature -Name $FeatureName
    If ($feature) {
        If ($feature.Where({$_.InstallState -eq 'Available'})) {
            Try {
                $result = Install-WindowsFeature -Name $FeatureName -IncludeAllSubFeature:$IncludeAllSubFeature -IncludeManagementTools:$IncludeManagementTools -Restart:$Restart -WhatIf:$WhatIf
                $success = $result -AND $result.Success
                $status = if ($success) { [InstallStatus]::Succeeded } Else { [InstallStatus]::Failed }
            }
            Catch {
                If ($success -AND $Restart -AND $result.restartNeeded -eq 'Yes') {
                    $status = [InstallStatus]::Pending
                    $error.clear()
                } Else {
                    Throw
                }
            }
        } Else {
            $success = $True
            $status = [InstallStatus]::AlreadyInstalled
        }
    } Else {
        $success = $False
        $status = [InstallStatus]::NoSuchFeature
    }
    
    @{ 'success' = $success ; 'status' = $status ; 'result' = $result }
    
}