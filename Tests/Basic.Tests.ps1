[CmdletBinding()]
param(
    [Parameter(Mandatory=$False)]
    [System.Collections.Hashtable]$TestResources
)

# NOTE: `Set-BuildEnvironment -Force -Path $PSScriptRoot` from build.ps1 makes the following $env: available:
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\WinAdminCenterPS\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "WinAdminCenterPS"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\WinAdminCenterPS\WinAdminCenterPS\WinAdminCenterPS.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\WinAdminCenterPS\WinAdminCenterPS"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\WinAdminCenterPS\BuildOutput"
#>

# Verbose output for non-master builds on appveyor
# Handy for troubleshooting.
# Splat @Verbose against commands as needed (here or in pester tests)
$Verbose = @{}
if($env:BHBranchName -notlike "master" -or $env:BHCommitMessage -match "!verbose") {
    $Verbose.add("Verbose",$True)
}

# Make sure the Module is not already loaded
if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force
}

Describe -Name "General Project Validation: $env:BHProjectName" -Tag 'Validation' -Fixture {
    $Scripts = Get-ChildItem $env:BHProjectPath -Include *.ps1,*.psm1,*.psd1 -Recurse

    # TestCases are splatted to the script so we need hashtables
    $TestCasesHashTable = $Scripts | foreach {@{file=$_}}         
    It "Script <file> should be valid powershell" -TestCases $TestCasesHashTable {
        param($file)

        $file.fullname | Should Exist

        $contents = Get-Content -Path $file.fullname -ErrorAction Stop
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
        $errors.Count | Should Be 0
    }

    It "Module '$env:BHProjectName' Should Load" -Test {
        {Import-Module $env:BHPSModuleManifest -Force} | Should Not Throw
    }

    It "Module '$env:BHProjectName' Public and Not Private Functions Are Available" {
        $Module = Get-Module $env:BHProjectName
        $Module.Name -eq $env:BHProjectName | Should Be $True
        $Commands = $Module.ExportedCommands.Keys
        $Commands -contains 'GetElevation' | Should Be $False
        
        $Commands -contains 'Add-FolderShare' | Should Be $True
        $Commands -contains 'Add-FolderShareNameUser' | Should Be $True
        $Commands -contains 'Add-FolderShareUser' | Should Be $True
        $Commands -contains 'Add-ScheduledTaskAction' | Should Be $True
        $Commands -contains 'Add-ScheduledTaskTrigger' | Should Be $True
        $Commands -contains 'Add-UserToLocalGroups' | Should Be $True
        $Commands -contains 'Clear-EventLogChannel' | Should Be $True
        $Commands -contains 'Clear-LogChannelAfterExport' | Should Be $True
        $Commands -contains 'Compress-ArchiveFileSystemEntity' | Should Be $True
        $Commands -contains 'Disable-CimPnpEntity' | Should Be $True
        $Commands -contains 'Disable-FirewallRule' | Should Be $True
        $Commands -contains 'Disable-ScheduledTask' | Should Be $True
        $Commands -contains 'Dismount-StorageVHD' | Should Be $True
        $Commands -contains 'Edit-FirewallRule' | Should Be $True
        $Commands -contains 'Edit-FolderShareInheritanceFlag' | Should Be $True
        $Commands -contains 'Edit-FolderShareUser' | Should Be $True
        $Commands -contains 'Edit-StorageVolume' | Should Be $True
        $Commands -contains 'Enable-CimPnpEntity' | Should Be $True
        $Commands -contains 'Enable-FirewallRule' | Should Be $True
        $Commands -contains 'Enable-ScheduledTask' | Should Be $True
        $Commands -contains 'Expand-ArchiveFileSystemEntity' | Should Be $True
        $Commands -contains 'Export-Certificate' | Should Be $True
        $Commands -contains 'Export-EventLogChannel' | Should Be $True
        $Commands -contains 'Export-RegistryContent' | Should Be $True
        $Commands -contains 'Find-DeviceDrivers' | Should Be $True
        $Commands -contains 'Find-WindowsUpdateList' | Should Be $True
        $Commands -contains 'Format-StorageVolume' | Should Be $True
        $Commands -contains 'Get-AntiMalwareSoftwareStatus' | Should Be $True
        $Commands -contains 'Get-AutomaticUpdatesOptions' | Should Be $True
        $Commands -contains 'Get-CertificateOverview' | Should Be $True
        $Commands -contains 'Get-Certificates' | Should Be $True
        $Commands -contains 'Get-CertificateScopes' | Should Be $True
        $Commands -contains 'Get-CertificateStores' | Should Be $True
        $Commands -contains 'Get-CertificateTreeNodes' | Should Be $True
        $Commands -contains 'Get-CimClassPnpEntity' | Should Be $True
        $Commands -contains 'Get-CimEventLogRecords' | Should Be $True
        $Commands -contains 'Get-CimMemorySummary' | Should Be $True
        $Commands -contains 'Get-CimNamespaceWithinMocrosoftWindows' | Should Be $True
        $Commands -contains 'Get-CimNetworkAdapterSummary' | Should Be $True
        $Commands -contains 'Get-CimPnpEntity' | Should Be $True
        $Commands -contains 'Get-CimPnpEntityDeviceProperties' | Should Be $True
        $Commands -contains 'Get-CimPnpEntityForDevice' | Should Be $True
        $Commands -contains 'Get-CimPnpSignedDriver' | Should Be $True
        $Commands -contains 'Get-CimProcess' | Should Be $True
        $Commands -contains 'Get-CimProcessorSummary' | Should Be $True
        $Commands -contains 'Get-CimRegistrySubKeys' | Should Be $True
        $Commands -contains 'Get-CimRegistryValues' | Should Be $True
        $Commands -contains 'Get-CimServiceDetail' | Should Be $True
        $Commands -contains 'Get-CimSingleService' | Should Be $True
        $Commands -contains 'Get-CimWin32ComputerSystem' | Should Be $True
        $Commands -contains 'Get-CimWin32LogicalDisk' | Should Be $True
        $Commands -contains 'Get-CimWin32NetworkAdapter' | Should Be $True
        $Commands -contains 'Get-CimWin32OperatingSystem' | Should Be $True
        $Commands -contains 'Get-CimWin32PhysicalMemory' | Should Be $True
        $Commands -contains 'Get-CimWin32Processor' | Should Be $True
        $Commands -contains 'Get-ClientConnectionStatus' | Should Be $True
        $Commands -contains 'Get-ClusterInventory' | Should Be $True
        $Commands -contains 'Get-ClusterNodes' | Should Be $True
        $Commands -contains 'Get-ComputerIdentification' | Should Be $True
        $Commands -contains 'Get-ComputerName' | Should Be $True
        $Commands -contains 'Get-DeviceDriverInformation' | Should Be $True
        $Commands -contains 'Get-DiskSummary' | Should Be $True
        $Commands -contains 'Get-DiskSummaryDownlevel' | Should Be $True
        $Commands -contains 'Get-EnvironmentVariables' | Should Be $True
        $Commands -contains 'Get-EventLogChannelStatus' | Should Be $True
        $Commands -contains 'Get-EventLogFilteredCount' | Should Be $True
        $Commands -contains 'Get-EventLogRecords' | Should Be $True
        $Commands -contains 'Get-EventLogSummary' | Should Be $True
        $Commands -contains 'Get-FileNamesInPath' | Should Be $True
        $Commands -contains 'Get-FileSystemEntities' | Should Be $True
        $Commands -contains 'Get-FileSystemRoot' | Should Be $True
        $Commands -contains 'Get-FirewallProfile' | Should Be $True
        $Commands -contains 'Get-FirewallRules' | Should Be $True
        $Commands -contains 'Get-FolderItemCount' | Should Be $True
        $Commands -contains 'Get-FolderOwner' | Should Be $True
        $Commands -contains 'Get-FolderShareNames' | Should Be $True
        $Commands -contains 'Get-FolderShareNameUserAccess' | Should Be $True
        $Commands -contains 'Get-FolderShareStatus' | Should Be $True
        $Commands -contains 'Get-FolderShareUsers' | Should Be $True
        $Commands -contains 'Get-HyperVEnhancedSessionModeSettings' | Should Be $True
        $Commands -contains 'Get-HyperVGeneralSettings' | Should Be $True
        $Commands -contains 'Get-HyperVHostPhysicalGpuSettings' | Should Be $True
        $Commands -contains 'Get-HyperVLiveMigrationSettings' | Should Be $True
        $Commands -contains 'Get-HyperVMigrationSupport' | Should Be $True
        $Commands -contains 'Get-HyperVNumaSpanningSettings' | Should Be $True
        $Commands -contains 'Get-HyperVRoleInstalled' | Should Be $True
        $Commands -contains 'Get-HyperVStorageMigrationSettings' | Should Be $True
        $Commands -contains 'Get-ItemProperties' | Should Be $True
        $Commands -contains 'Get-ItemType' | Should Be $True
        $Commands -contains 'Get-LocalGroups' | Should Be $True
        $Commands -contains 'Get-LocalGroupUsers' | Should Be $True
        $Commands -contains 'Get-LocalUserBelongGroups' | Should Be $True
        $Commands -contains 'Get-LocalUsers' | Should Be $True
        $Commands -contains 'Get-MemorySummaryDownLevel' | Should Be $True
        $Commands -contains 'Get-Networks' | Should Be $True
        $Commands -contains 'Get-NetworkSummaryDownlevel' | Should Be $True
        $Commands -contains 'Get-NumberOfLoggedOnUsers' | Should Be $True
        $Commands -contains 'Get-ProcessDownlevel' | Should Be $True
        $Commands -contains 'Get-Processes' | Should Be $True
        $Commands -contains 'Get-ProcessHandle' | Should Be $True
        $Commands -contains 'Get-ProcessModule' | Should Be $True
        $Commands -contains 'Get-ProcessorSummaryDownlevel' | Should Be $True
        $Commands -contains 'Get-ProcessService' | Should Be $True
        $Commands -contains 'Get-RbacSessionConfiguration' | Should Be $True
        $Commands -contains 'Get-RegistrySubKeys' | Should Be $True
        $Commands -contains 'Get-RegistryValues' | Should Be $True
        $Commands -contains 'Get-RemoteDesktop' | Should Be $True
        $Commands -contains 'Get-RolesAndFeatures' | Should Be $True
        $Commands -contains 'Get-ScheduledTasks' | Should Be $True
        $Commands -contains 'Get-ServerConnectionStatus' | Should Be $True
        $Commands -contains 'Get-ServerInventory' | Should Be $True
        $Commands -contains 'Get-ServiceImagePath' | Should Be $True
        $Commands -contains 'Get-ServiceList' | Should Be $True
        $Commands -contains 'Get-ServiceLogOnUser' | Should Be $True
        $Commands -contains 'Get-ServiceRecoveryOptions' | Should Be $True
        $Commands -contains 'Get-StorageDisk' | Should Be $True
        $Commands -contains 'Get-StorageFileShare' | Should Be $True
        $Commands -contains 'Get-StorageQuota' | Should Be $True
        $Commands -contains 'Get-StorageResizeDetails' | Should Be $True
        $Commands -contains 'Get-StorageVolume' | Should Be $True
        $Commands -contains 'Get-TempFolder' | Should Be $True
        $Commands -contains 'Get-TempFolderPath' | Should Be $True
        $Commands -contains 'Get-TemporaryFolder' | Should Be $True
        $Commands -contains 'Get-WindowsUpdateInstallerStatus' | Should Be $True
        $Commands -contains 'Import-Certificate' | Should Be $True
        $Commands -contains 'Import-RegistryContent' | Should Be $True
        $Commands -contains 'Initialize-StorageDisk' | Should Be $True
        $Commands -contains 'Install-DeviceDriver' | Should Be $True
        $Commands -contains 'Install-RolesAndFeatures' | Should Be $True
        $Commands -contains 'Install-StorageFSRM' | Should Be $True
        $Commands -contains 'Install-WindowsUpdates' | Should Be $True
        $Commands -contains 'Mount-StorageVHD' | Should Be $True
        $Commands -contains 'New-BasicTask' | Should Be $True
        $Commands -contains 'New-CimProcessDump' | Should Be $True
        $Commands -contains 'New-EnvironmentVariable' | Should Be $True
        $Commands -contains 'New-FirewallRule' | Should Be $True
        $Commands -contains 'New-Folder' | Should Be $True
        $Commands -contains 'New-LocalGroup' | Should Be $True
        $Commands -contains 'New-LocalUser' | Should Be $True
        $Commands -contains 'New-ProcessDumpDownlevel' | Should Be $True
        $Commands -contains 'New-RegistryKey' | Should Be $True
        $Commands -contains 'New-RegistryValue' | Should Be $True
        $Commands -contains 'New-StorageQuota' | Should Be $True
        $Commands -contains 'New-StorageVHD' | Should Be $True
        $Commands -contains 'New-StorageVolume' | Should Be $True
        $Commands -contains 'Remove-AllShareNames' | Should Be $True
        $Commands -contains 'Remove-Certificate' | Should Be $True
        $Commands -contains 'Remove-EnvironmentVariable' | Should Be $True
        $Commands -contains 'Remove-FilePath' | Should Be $True
        $Commands -contains 'Remove-FileSystemEntity' | Should Be $True
        $Commands -contains 'Remove-FirewallRule' | Should Be $True
        $Commands -contains 'Remove-FolderShareUser' | Should Be $True
        $Commands -contains 'Remove-ItemByPath' | Should Be $True
        $Commands -contains 'Remove-LocalGroup' | Should Be $True
        $Commands -contains 'Remove-LocalUser' | Should Be $True
        $Commands -contains 'Remove-LocalUserFromLocalGroups' | Should Be $True
        $Commands -contains 'Remove-RegistryKey' | Should Be $True
        $Commands -contains 'Remove-RegistryValue' | Should Be $True
        $Commands -contains 'Remove-ScheduledTask' | Should Be $True
        $Commands -contains 'Remove-ScheduledTaskAction' | Should Be $True
        $Commands -contains 'Remove-StorageQuota' | Should Be $True
        $Commands -contains 'Remove-StorageVolume' | Should Be $True
        $Commands -contains 'Remove-UsersFromLocalGroup' | Should Be $True
        $Commands -contains 'Rename-FileSystemEntity' | Should Be $True
        $Commands -contains 'Rename-LocalGroup' | Should Be $True
        $Commands -contains 'Rename-RegistryKey' | Should Be $True
        $Commands -contains 'Rename-RegistryValue' | Should Be $True
        $Commands -contains 'Resize-StorageVolume' | Should Be $True
        $Commands -contains 'Restart-CimOperatingSystem' | Should Be $True
        $Commands -contains 'Resume-CimService' | Should Be $True
        $Commands -contains 'Search-RegistryKeyAndValue' | Should Be $True
        $Commands -contains 'Set-AutomaticUpdatesOptions' | Should Be $True
        $Commands -contains 'Set-ComputerIdentification' | Should Be $True
        $Commands -contains 'Set-DeviceState' | Should Be $True
        $Commands -contains 'Set-DHCPIP' | Should Be $True
        $Commands -contains 'Set-EnvironmentVariable' | Should Be $True
        $Commands -contains 'Set-HyperVEnhancedSessionModeSettings' | Should Be $True
        $Commands -contains 'Set-HyperVHostGeneralSettings' | Should Be $True
        $Commands -contains 'Set-HyperVHostLiveMigrationSettings' | Should Be $True
        $Commands -contains 'Set-HyperVHostNumaSpanningSettings' | Should Be $True
        $Commands -contains 'Set-HyperVHostStorageMigrationSettings' | Should Be $True
        $Commands -contains 'Set-LocalGroupProperties' | Should Be $True
        $Commands -contains 'Set-LocalUserPassword' | Should Be $True
        $Commands -contains 'Set-LocalUserProperties' | Should Be $True
        $Commands -contains 'Set-RegistryValue' | Should Be $True
        $Commands -contains 'Set-RemoteDesktop' | Should Be $True
        $Commands -contains 'Set-ScheduledTaskConditions' | Should Be $True
        $Commands -contains 'Set-ScheduledTaskGeneralSettings' | Should Be $True
        $Commands -contains 'Set-ScheduledTaskSettingsSet' | Should Be $True
        $Commands -contains 'Set-ServiceLogOnUser' | Should Be $True
        $Commands -contains 'Set-ServiceRecoveryOptions' | Should Be $True
        $Commands -contains 'Set-ServiceStartOptions' | Should Be $True
        $Commands -contains 'Set-StaticIP' | Should Be $True
        $Commands -contains 'Set-StorageDiskOffline' | Should Be $True
        $Commands -contains 'Start-CimProcess' | Should Be $True
        $Commands -contains 'Start-CimService' | Should Be $True
        $Commands -contains 'Start-DiskPerf' | Should Be $True
        $Commands -contains 'Start-ProcessDownlevel' | Should Be $True
        $Commands -contains 'Start-ScheduledTask' | Should Be $True
        $Commands -contains 'Stop-CimOperatingSystem' | Should Be $True
        $Commands -contains 'Stop-CimProcess' | Should Be $True
        $Commands -contains 'Stop-DiskPerf' | Should Be $True
        $Commands -contains 'Stop-Processes' | Should Be $True
        $Commands -contains 'Stop-ScheduledTask' | Should Be $True
        $Commands -contains 'Stop-ServiceByName' | Should Be $True
        $Commands -contains 'Suspend-CimService' | Should Be $True
        $Commands -contains 'Test-FileSystemEntity' | Should Be $True
        $Commands -contains 'Test-RegistryValueExists' | Should Be $True
        $Commands -contains 'Uninstall-RolesAndFeatures' | Should Be $True
        $Commands -contains 'Update-Certificate' | Should Be $True
        $Commands -contains 'Update-DeviceDriver' | Should Be $True
        $Commands -contains 'Update-ScheduledTaskAction' | Should Be $True
        $Commands -contains 'Update-ScheduledTaskTrigger' | Should Be $True
        $Commands -contains 'Update-StorageQuota' | Should Be $True
    }

    It "Module '$env:BHProjectName' Private Functions Are Available in Internal Scope" {
        $Module = Get-Module $env:BHProjectName
        [bool]$Module.Invoke({Get-Item function:GetElevation}) | Should Be $True
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHxptPPhPOJw43BQKb7ifcAy1
# heegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDUjxCP0kmFpLOhD
# shsd5NYEhHf9MA0GCSqGSIb3DQEBAQUABIIBAGI5g08rAQu9/A5w9RqmxgYnF8ey
# AQEOPgfhc5zq7F13V+UUw4hsNnl4zc0TwHa0nDDk0VybnR+ns6obNwXd/erjIJg6
# UtB2/mswtw3QORlSRy72n7A2jgmrHm+XF1s1pNM/prl92VLSvBIJEQ3kT+8Iur+C
# 0mlanGCGg3I1oU0Ifilq7ZdnB1aqDDu5G9lf+Lvo5ubaWEbe51+tEdsaplpRMSvO
# xP+/M+tB9x9Ex7msVbMs03fI+fRB3FaDRoJbWCuwi3SOBHmvuGkHWlClvmWXFp4e
# yidamy0TocWa0wxNV5JBDi7EabttvlCG4m7ivL153TYJ2Vifb9l4HXTOtNw=
# SIG # End signature block
