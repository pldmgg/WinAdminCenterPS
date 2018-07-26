<#
    
    .SYNOPSIS
        Get Disk summary by using ManagementTools CIM provider.
    
    .DESCRIPTION
        Get Disk summary by using ManagementTools CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-DiskSummary {
    import-module CimCmdlets
    
    $ReadResult = (get-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Services\partmgr -Name EnableCounterForIoctl -ErrorAction SilentlyContinue)
    if (!$ReadResult -or $ReadResult.EnableCounterForIoctl -ne 1) {
        # no disk performance counters enabled.
        return
    }
    
    $instances = Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTDisk
    if ($instances -ne $null) {
        $instances | ForEach-Object {
            $instance = ($_ | Microsoft.PowerShell.Utility\Select-Object ActiveTime, AverageResponseTime, Capacity, CurrentIndex, DiskNumber, IntervalSeconds, Name, ReadTransferRate, WriteTransferRate)
            $volumes = ($_.Volumes | Microsoft.PowerShell.Utility\Select-Object FormattedSize, PageFile, SystemDisk, VolumePath)
            $instance | Add-Member -NotePropertyName Volumes -NotePropertyValue $volumes
            $instance
        }
    }    
}