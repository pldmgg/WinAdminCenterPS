<#
    
    .SYNOPSIS
        Gets memory summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets memory summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-MemorySummaryDownLevel {
    import-module CimCmdlets
    
    # reset counter reading only first one.
    function Reset($counter) {
        $Global:Utilization = [System.Collections.ArrayList]@()
        for ($i = 0; $i -lt 59; $i++) {
            $Global:Utilization.Insert(0, 0)
        }
    
        $Global:Utilization.Insert(0, $counter)
        $Global:Delta = 0
    }
    
    $memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $now = get-date
    $system = Get-CimInstance Win32_ComputerSystem
    $percent = 100 * ($system.TotalPhysicalMemory - $memory.AvailableBytes) / $system.TotalPhysicalMemory
    $cached = $memory.StandbyCacheCoreBytes + $memory.StandbyCacheNormalPriorityBytes + $memory.StandbyCacheReserveBytes + $memory.ModifiedPageListBytes
    
    # get sampling time and remember last sample time.
    if (-not $Global:SampleTime) {
        $Global:SampleTime = $now
        $Global:LastTime = $Global:SampleTime
        Reset($percent)
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = $now
        if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            Reset($percent)
        }
        else {
            $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
            while ($Global:Delta -gt 1000) {
                $Global:Delta -= 1000
                $Global:Utilization.Insert(0, $percent)
            }
    
            $Global:Utilization = $Global:Utilization.GetRange(0, 60)
        }
    }
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "Available" $memory.AvailableBytes
    $result | Add-Member -MemberType NoteProperty -Name "Cached" $cached
    $result | Add-Member -MemberType NoteProperty -Name "Total" $system.TotalPhysicalMemory
    $result | Add-Member -MemberType NoteProperty -Name "InUse" ($system.TotalPhysicalMemory - $memory.AvailableBytes)
    $result | Add-Member -MemberType NoteProperty -Name "Committed" $memory.CommittedBytes
    $result | Add-Member -MemberType NoteProperty -Name "PagedPool" $memory.PoolPagedBytes
    $result | Add-Member -MemberType NoteProperty -Name "NonPagedPool" $memory.PoolNonpagedBytes
    $result | Add-Member -MemberType NoteProperty -Name "Utilization" $Global:Utilization
    $result
}