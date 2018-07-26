<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V migration support.
    
    .DESCRIPTION
        Gets a computer's Hyper-V  migration support.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVMigrationSupport {
    Set-StrictMode -Version 5.0
    
    $migrationSettingsDatas=Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Query "associators of {Msvm_VirtualSystemMigrationCapabilities.InstanceID=""Microsoft:MigrationCapabilities""} where resultclass = Msvm_VirtualSystemMigrationSettingData"
    
    $live = $false;
    $storage = $false;
    
    foreach ($migrationSettingsData in $migrationSettingsDatas) {
        if ($migrationSettingsData.MigrationType -eq 32768) {
            $live = $true;
        }
    
        if ($migrationSettingsData.MigrationType -eq 32769) {
            $storage = $true;
        }
    }
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "liveMigrationSupported" $live;
    $result | Add-Member -MemberType NoteProperty -Name "storageMigrationSupported" $storage;
    $result
}