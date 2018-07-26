<#
    
    .SYNOPSIS
        Gets a list of Features / Roles / Role Services on the target server.
    
    .DESCRIPTION
        The data returned for each includes name, description, installstate, installed.
        Can be called with a FeatureName or FeatureType both of which are optional.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .EXAMPLE
        Get-RolesAndFeatures
        When called with no parameters, returns data for all roles, features and role services available on the server
    
    .EXAMPLE
        Get-RolesAndFeatures -FeatureName 'Web-Server'
        When called with a FeatureName (e.g. Web-Server) returns details for the given feature if it is available
    
    .EXAMPLE
        Get-RolesAndFeatures -FeatureType 'Role'
        When called with a FeatureType ('Role', 'Feature' or 'Role Service) returns details for all avilable features
        of that FeatureType
    
    .ROLE
        Readers
    
#>
function Get-RolesAndFeatures {
    param(
        [Parameter(Mandatory=$False)]
        [string]
        $FeatureName = '',
    
        [Parameter(Mandatory=$False)]
        [ValidateSet('Role', 'Role Service', 'Feature', IgnoreCase=$False)]
        [string]
        $FeatureType = ''
    )
    
    Import-Module ServerManager
    
    $result = $null
    
    if ($FeatureName) {
        $result = Get-WindowsFeature -Name $FeatureName
    }
    else {
        if ($FeatureType) {
            $result = Get-WindowsFeature | Where-Object { $_.FeatureType -EQ $FeatureType }
        } else {
            $result = Get-WindowsFeature
        }
    }
    
    $result
    
}