[![Build status](https://ci.appveyor.com/api/projects/status/github/pldmgg/winadmincenterps?branch=master&svg=true)](https://ci.appveyor.com/project/pldmgg/WinAdminCenterPS/branch/master)


# WinAdminCenterPS
Copy of  Windows Admin Center (https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/overview) PowerShell Functions.

## Getting Started

```powershell
# One time setup
    # Download the repository
    # Unblock the zip
    # Extract the WinAdminCenterPS folder to a module path (e.g. $env:USERPROFILE\Documents\WindowsPowerShell\Modules\)

# Import the module.
    Import-Module WinAdminCenterPS    # Alternatively, Import-Module <PathToModuleFolder>

# Get commands in the module
    Get-Command -Module WinAdminCenterPS

```

## Functions Used in the Overview Tab
|Overview Functions 1|Overview Functions 2|Overview Functions 3|
|--------------------|--------------------|--------------------|
|Get-AntimalwareSoftwareStatus|Get-CimMemorySummary|Get-CimNetworkAdapterSummary|
|Get-CimProcessorSummary|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClientConnectionStatus|Get-ClusterInventory|
|Get-ClusterNodes|Get-ComputerIdentification|Get-DiskSummary|
|Get-DiskSummaryDownlevel|Get-EnvironmentVariables|Get-HyperVEnhancedSessionModeSettings|
|Get-HyperVGeneralSettings|Get-HyperVHostPhysicalGpuSettings|Get-HyperVLiveMigrationSettings|
|Get-HyperVMigrationSupport|Get-HyperVNumaSpanningSettings|Get-HyperVRoleInstalled|
|Get-HyperVStorageMigrationSettings|Get-MemorySummaryDownLevel|Get-NetworkSummaryDownlevel|
|Get-NumberOfLoggedOnUsers|Get-ProcessorSummaryDownlevel|Get-RbacSessionConfiguration|
|Get-RemoteDesktop|Get-ServerConnectionStatus|Get-ServerInventory|
|New-EnvironmentVariable|Remove-EnvironmentVariable|Restart-CimOperatingSystem|
|Set-ComputerIdentification|Set-EnvironmentVariable|Set-HyperVEnhancedSessionModeSettings|
|Set-HyperVHostGeneralSettings|Set-HyperVHostLiveMigrationSettings|Set-HyperVHostNumaSpanningSettings|
|Set-HyperVHostStorageMigrationSettings|Set-RemoteDesktop|Start-DiskPerf|Stop-CimOperatingSystem|Stop-DiskPerf

## Functions Used in the Certificates Tab

|Certificates Functions 1|Certificates Functions 2|Certificates Functions 3|
|------------------------|------------------------|------------------------|
|Clear-EventLogChannel|Clear-EventLogChannelAfterExport|Export-Certificate|
|Export-EventLogChannel|Get-CertificateOverview|Get-Certificates|
|Get-CertificateScopes|Get-CertificateStores|Get-CertificateTreeNodes|
|Get-CimEventLogRecords|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClusterInventory|Get-ClusterNodes|
|Get-EventLogFilteredCount|Get-EventLogRecords|Get-EventLogSummary|
|Get-ServerInventory|Get-TempFolder|Import-Certificate|
|Remove-Certificate|Remove-ItemByPath|Set-EventLogChannelStatus|
|Update-Certificate|

## Functions Used in the Devices Tab

|Devices Functions 1|Devices Functions 2|Devices Functions 3|
|-------------------|-------------------|-------------------|
|Disable-CimPnpEntity|Enable-CimPnpEntity|Find-DeviceDrivers|
|Get-CimClassPnpEntity|Get-CimPnpEntity|Get-CimPnpEntityDeviceProperties|
|Get-CimPnpEntityForDevice|Get-CimPnpSignedDriver|Get-CimWin32ComputerSystem|
|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|
|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|Get-ClusterInventory|
|Get-ClusterNodes|Get-DeviceDriverInformation|Get-ServerInventory|
|Install-DeviceDriver|Set-DeviceState|Update-DeviceDriver|

## Functions Used in the Events Tab

|Events Functions 1|Events Functions 2|Events Functions 3|
|------------------|------------------|------------------|
|Clear-EventLogChannel|Clear-EventLogChannelAfterExport|Export-EventLogChannel|
|Get-CimEventLogRecords|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClusterInventory|Get-ClusterNodes|
|Get-EventLogFilteredCount|Get-EventLogRecords|Get-EventLogSummary|
|Get-ServerInventory|Set-EventLogChannelStatus|

## Functions Used in the Files Tab

|Files Functions 1|Files Functions 2|Files Functions 3|
|-----------------|-----------------|-----------------|
|Add-FolderShare|Add-FolderShareNameUser|Add-FolderShareUser|
|Compress-ArchiveFileSystemEntity|Edit-FolderShareInheritanceFlag|Edit-FolderShareUser|
|Expand-ArchiveFileSystemEntity|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClusterInventory|Get-ClusterNodes|
|Get-ComputerName|Get-FileNamesInPath|Get-FileSystemEntities|
|Get-FileSystemRoot|Get-FolderItemCount|Get-FolderOwner|
|Get-FolderShareNames|Get-FolderShareNameUserAccess|Get-FolderShareStatus|
|Get-FolderShareUsers|Get-ItemProperties|Get-ItemType|
|Get-ServerInventory|Get-TempFolderPath|New-Folder|
|Remove-AllShareNames|Remove-FileSystemEntity|Remove-FolderShareUser|
|Rename-FileSystemEntity|Test-FileSystemEntity

## Functions Used in the Firewall Tab

|Firewall Functions 1|Firewall Functions 2|Firewall Functions 3|
|--------------------|--------------------|--------------------|
|Disable-FirewallRule|Edit-FirewallRule|Enable-FirewallRule|
|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|
|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|
|Get-ClusterInventory|Get-ClusterNodes|Get-FirewallProfile|
|Get-FirewallRules|Get-ServerInventory|New-FirewallRule|
|Remove-FirewallRule|

## Functions Used in the Local Users & Groups Tab

|LocalUsersGroups Functions 1|LocalUsersGroups Functions 2|LocalUsersGroup Functions 3|
|----------------------------|----------------------------|---------------------------|
|Add-UserToLocalGroups|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClusterInventory|Get-ClusterNodes|
|Get-LocalGroups|Get-LocalGroupUsers|Get-LocalUserBelongGroups|
|Get-LocalUsers|Get-ServerInventory|New-LocalGroup|
|New-LocalUser|Remove-LocalGroup|Remove-LocalUser|
|Remove-LocalUserFromLocalGroups|Remove-UsersFromLocalGroup|Rename-LocalGroup|
|Set-LocalGroupProperties|Set-LocalUserPassword|Set-LocalUserProperties|

## Functions Used in the Network Tab

|Network Functions 1|Network Functions 2|Network Functions 3|
|-------------------|-------------------|-------------------|
|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|
|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|
|Get-ClusterInventory|Get-ClusterNodes|Get-Networks|
|Get-ServerInventory|Set-DhcpIP|Set-StaticIP

## Functions Used in the Processes Tab

|Processes Functions 1|Processes Functions 2|Processes Functions 3|
|---------------------|---------------------|---------------------|
|Get-CimNamespaceWithinMicrosoftWindows|Get-CimProcess|Get-CimWin32ComputerSystem|
|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|
|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|Get-ClusterInventory|
|Get-ClusterNodes|Get-ProcessDownlevel|Get-Processes|
|Get-ProcessHandle|Get-ProcessModule|Get-ProcessService|
|Get-ServerInventory|New-CimProcessDump|New-ProcessDumpDownlevel|
|Start-CimProcess|Start-ProcessDownlevel|Stop-CimProcess|
|Stop-Processes|

## Functions Used in the Registry Tab

|Registry Functions 1|Registry Functions 2|Registry Functions 3|
|--------------------|--------------------|--------------------|
|Export-RegistryContent|Get-CimRegistrySubKeys|Get-CimRegistryValues|
|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|
|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|
|Get-ClusterInventory|Get-ClusterNodes|Get-RegistrySubKeys|
|Get-RegistryValues|Get-ServerInventory|Get-TemporaryFolder|
|Import-RegistryContent|New-RegistryKey|New-RegistryValue|
|Remove-FilePath|Remove-RegistryKey|Remove-RegistryValue|
|Rename-RegistryKey|Rename-RegistryValue|Search-RegistryKeyAndValue|
|Set-RegistryValue|Test-RegistryValueExists|

## Functions Used in the Roles & Features Tab

|RolesFeatures Functions 1|RolesFeatures Functions 2|RolesFeatures Functions 3|
|-------------------------|-------------------------|-------------------------|
|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|
|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|
|Get-ClusterInventory|Get-ClusterNodes|Get-RolesAndFeatures|
|Get-ServerInventory|Install-RolesAndFeatures|Uninstall-RolesAndFeatures|

## Functions Used in the Scheduled Tasks Tab

|ScheduledTasks Functions 1|ScheduledTasks Functions 2|ScheduledTasks Functions 3|
|--------------------------|--------------------------|--------------------------|
|Add-ScheduledTaskAction|Add-ScheduledTaskTrigger|Disable-ScheduledTask|
|Enable-ScheduledTask|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClusterInventory|Get-ClusterNodes|
|Get-ScheduledTasks|Get-ServerInventory|New-BasicTask|
|Remove-ScheduledTask|Remove-ScheduledTaskAction|Set-ScheduledTaskConditions|
|Set-ScheduledTaskGeneralSettings|Set-ScheduledTaskSettingsSet|Start-ScheduledTask|
|Stop-ScheduledTask|Update-ScheduledTaskAction|Update-ScheduledTaskTrigger|

## Functions Used in the Services Tab

|Services Functions 1|Services Functions 2|Services Functions 3|
|--------------------|--------------------|--------------------|
|Get-CimServiceDetail|Get-CimSingleService|Get-CimWin32ComputerSystem|
|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|
|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|Get-ClusterInventory|
|Get-ClusterNodes|Get-ServerInventory|Get-ServiceImagePath|
|Get-ServiceList|Get-ServiceLogOnUser|Get-ServiceRecoveryOptions|
|Resume-CimService|Set-ServiceLogOnUser|Set-ServiceRecoveryOptions|
|Set-ServiceStartOptions|Start-CimService|Stop-ServiceByName|
|Suspend-CimService|

## Functions Used in the Storage Tab

|Storage Functions 1|Storage Functions 2|Storage Functions 3|
|-------------------|-------------------|-------------------|
|Add-FolderShare|Add-FolderShareNameUser|Add-FolderShareUser|
|Compress-ArchiveFileSystemEntity|Dismount-StorageVHD|Edit-FolderShareInheritanceFlag|
|Edit-FolderShareUser|Edit-StorageVolume|Expand-ArchiveFileSystemEntity|
|Format-StorageVolume|Get-CimWin32ComputerSystem|Get-CimWin32LogicalDisk|
|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|Get-CimWin32PhysicalMemory|
|Get-CimWin32Processor|Get-ClusterInventory|Get-ClusterNodes|
|Get-ComputerName|Get-FileNamesInPath|Get-FileSystemEntities|
|Get-FileSystemRoot|Get-FolderItemCount|Get-FolderOwner|
|Get-FolderShareNames|Get-FolderShareNameUserAccess|Get-FolderShareStatus|
|Get-FolderShareUsers|Get-ItemProperties|Get-ItemType|
|Get-ServerInventory|Get-StorageDisk|Get-StorageFileShare|
|Get-StorageQuota|Get-StorageResizeDetails|Get-StorageVolume|
|Get-TempFolderPath|Initialize-StorageDisk|Install-StorageFSRM|
|Mount-StorageVHD|New-Folder|New-StorageQuota|
|New-StorageVHD|New-StorageVolume|Remove-AllShareNames|
|Remove-FileSystemEntity|Remove-FolderShareUser|Remove-StorageQuota|
|Remove-StorageVolume|Rename-FileSystemEntity|Resize-StorageVolume|
|Set-StorageDiskOffline|Test-FileSystemEntity|Update-StorageQuota|

## Functions Used in the Updates Tab

|Updates Functions 1|Updates Functions 2|Updates Functions 3|
|-------------------|-------------------|-------------------|
|Find-WindowsUpdateList|Get-AutomaticUpdatesOptions|Get-CimWin32ComputerSystem|
|Get-CimWin32LogicalDisk|Get-CimWin32NetworkAdapter|Get-CimWin32OperatingSystem|
|Get-CimWin32PhysicalMemory|Get-CimWin32Processor|Get-ClusterInventory|
|Get-ClusterNodes|Get-ServerInventory|Get-WindowsUpdateInstallerStatus|
|Install-WindowsUpdates|Set-AutomaticUpdatesOptions|

## Notes

* PSGallery: 
