<#
    
    .SYNOPSIS
        Gets disk summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets disk summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-DiskSummaryDownlevel {
    param
    (
    )
    
    import-module CimCmdlets
    
    function ResetDiskData($diskResults) {
        $Global:DiskResults = @{}
        $Global:DiskDelta = 0
    
        foreach ($item in $diskResults) {
            $diskRead = New-Object System.Collections.ArrayList
            $diskWrite = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt 60; $i++) {
                $diskRead.Insert(0, 0)
                $diskWrite.Insert(0, 0)
            }
    
            $Global:DiskResults.Item($item.name) = @{
                ReadTransferRate  = $diskRead
                WriteTransferRate = $diskWrite
            }
        }
    }
    
    function UpdateDiskData($diskResults) {
        $Global:DiskDelta += ($Global:DiskSampleTime - $Global:DiskLastTime).TotalMilliseconds
    
        foreach ($diskResult in $diskResults) {
            $localDelta = $Global:DiskDelta
    
            # update data for each disk
            $item = $Global:DiskResults.Item($diskResult.name)
    
            if ($item -ne $null) {
                while ($localDelta -gt 1000) {
                    $localDelta -= 1000
                    $item.ReadTransferRate.Insert(0, $diskResult.DiskReadBytesPersec)
                    $item.WriteTransferRate.Insert(0, $diskResult.DiskWriteBytesPersec)
                }
    
                $item.ReadTransferRate = $item.ReadTransferRate.GetRange(0, 60)
                $item.WriteTransferRate = $item.WriteTransferRate.GetRange(0, 60)
    
                $Global:DiskResults.Item($diskResult.name) = $item
            }
        }
    
        $Global:DiskDelta = $localDelta
    }
    
    $counterValue = Get-CimInstance win32_perfFormattedData_PerfDisk_PhysicalDisk -Filter "name!='_Total'" | Microsoft.PowerShell.Utility\Select-Object name, DiskReadBytesPersec, DiskWriteBytesPersec
    $now = get-date
    
    # get sampling time and remember last sample time.
    if (-not $Global:DiskSampleTime) {
        $Global:DiskSampleTime = $now
        $Global:DiskLastTime = $Global:DiskSampleTime
        ResetDiskData($counterValue)
    }
    else {
        $Global:DiskLastTime = $Global:DiskSampleTime
        $Global:DiskSampleTime = $now
        if ($Global:DiskSampleTime - $Global:DiskLastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            ResetDiskData($counterValue)
        }
        else {
            UpdateDiskData($counterValue)
        }
    }
    
    $Global:DiskResults
}