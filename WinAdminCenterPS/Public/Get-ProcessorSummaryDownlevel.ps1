<#
    
    .SYNOPSIS
        Gets processor summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets processor summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ProcessorSummaryDownlevel {
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
    
    $processorCounter = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "name='_Total'"
    $now = get-date
    $processor = Get-CimInstance Win32_Processor
    $os = Get-CimInstance Win32_OperatingSystem
    $processes = Get-CimInstance Win32_Process
    $percent = $processorCounter.PercentProcessorTime
    $handles = 0
    $threads = 0
    $processes | ForEach-Object { $handles += $_.HandleCount; $threads += $_.ThreadCount }
    $uptime = ($now - $os.LastBootUpTime).TotalMilliseconds * 10000
    
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
    $result | Add-Member -MemberType NoteProperty -Name "Name" $processor[0].Name
    $result | Add-Member -MemberType NoteProperty -Name "AverageSpeed" ($processor[0].CurrentClockSpeed / 1000)
    $result | Add-Member -MemberType NoteProperty -Name "Processes" $processes.Length
    $result | Add-Member -MemberType NoteProperty -Name "Uptime" $uptime
    $result | Add-Member -MemberType NoteProperty -Name "Handles" $handles
    $result | Add-Member -MemberType NoteProperty -Name "Threads" $threads
    $result | Add-Member -MemberType NoteProperty -Name "Utilization" $Global:Utilization
    $result
}