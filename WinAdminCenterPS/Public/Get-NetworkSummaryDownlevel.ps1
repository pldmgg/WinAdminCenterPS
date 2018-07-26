<#
    
    .SYNOPSIS
        Gets network adapter summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets network adapter summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-NetworkSummaryDownlevel {
    import-module CimCmdlets
    function ResetData($adapterResults) {
        $Global:NetworkResults = @{}
        $Global:PrevAdapterData = @{}
        $Global:Delta = 0
    
        foreach ($key in $adapterResults.Keys) {
            $adapterResult = $adapterResults.Item($key)
            $sentBytes = New-Object System.Collections.ArrayList
            $receivedBytes = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt 60; $i++) {
                $sentBytes.Insert(0, 0)
                $receivedBytes.Insert(0, 0)
            }
    
            $networkResult = @{
                SentBytes = $sentBytes
                ReceivedBytes = $receivedBytes
            }
            $Global:NetworkResults.Item($key) = $networkResult
        }
    }
    
    function UpdateData($adapterResults) {
        $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
    
        foreach ($key in $adapterResults.Keys) {
            $localDelta = $Global:Delta
    
            # update data for each adapter
            $adapterResult = $adapterResults.Item($key)
            $item = $Global:NetworkResults.Item($key)
            if ($item -ne $null) {
                while ($localDelta -gt 1000) {
                    $localDelta -= 1000
                    $item.SentBytes.Insert(0, $adapterResult.SentBytes)
                    $item.ReceivedBytes.Insert(0, $adapterResult.ReceivedBytes)
                }
    
                $item.SentBytes = $item.SentBytes.GetRange(0, 60)
                $item.ReceivedBytes = $item.ReceivedBytes.GetRange(0, 60)
    
                $Global:NetworkResults.Item($key) = $item
            }
        }
    
        $Global:Delta = $localDelta
    }
    
    $adapters = Get-CimInstance -Namespace root/standardCimV2 MSFT_NetAdapter | Where-Object MediaConnectState -eq 1 | Microsoft.PowerShell.Utility\Select-Object Name, InterfaceIndex, InterfaceDescription
    $activeAddresses = get-CimInstance -Namespace root/standardCimV2 MSFT_NetIPAddress | Microsoft.PowerShell.Utility\Select-Object interfaceIndex
    
    $adapterResults = @{}
    foreach ($adapter in $adapters) {
        foreach ($activeAddress in $activeAddresses) {
            # Find a match between the 2
            if ($adapter.InterfaceIndex -eq $activeAddress.interfaceIndex) {
                $description = $adapter | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty interfaceDescription
    
                if ($Global:UsePerfData -EQ $NULL) {
                    $adapterData = Get-CimInstance -Namespace root/StandardCimv2 MSFT_NetAdapterStatisticsSettingData -Filter "Description='$description'" | Microsoft.PowerShell.Utility\Select-Object ReceivedBytes, SentBytes
    
                    if ($adapterData -EQ $null) {
                        # If above doesnt return data use slower perf data below
                        $Global:UsePerfData = $true
                    }
                }
    
                if ($Global:UsePerfData -EQ $true) {
                    # Need to replace the '#' to ascii since we parse anything after # as a comment
                    $sanitizedDescription = $description -replace [char]35, "_"
                    $adapterData = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkAdapter | Where-Object name -EQ $sanitizedDescription | Microsoft.PowerShell.Utility\Select-Object BytesSentPersec, BytesReceivedPersec
    
                    $sentBytes = $adapterData.BytesSentPersec
                    $receivedBytes = $adapterData.BytesReceivedPersec
                }
                else {
                    # set to 0 because we dont have a baseline to subtract from
                    $sentBytes = 0
                    $receivedBytes = 0
    
                    if ($Global:PrevAdapterData -ne $null) {
                        $prevData = $Global:PrevAdapterData.Item($description)
                        if ($prevData -ne $null) {
                            $sentBytes = $adapterData.SentBytes - $prevData.SentBytes
                            $receivedBytes = $adapterData.ReceivedBytes - $prevData.ReceivedBytes
                        }
                    }
                    else {
                        $Global:PrevAdapterData = @{}
                    }
    
                    # Now that we have data, set current data as previous data as baseline
                    $Global:PrevAdapterData.Item($description) = $adapterData
                }
    
                $adapterResult = @{
                    SentBytes = $sentBytes
                    ReceivedBytes = $receivedBytes
                }
                $adapterResults.Item($description) = $adapterResult
                break;
            }
        }
    }
    
    $now = get-date
    
    if (-not $Global:SampleTime) {
        $Global:SampleTime = $now
        $Global:LastTime = $Global:SampleTime
        ResetData($adapterResults)
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = $now
        if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            ResetData($adapterResults)
        }
        else {
            UpdateData($adapterResults)
        }
    }
    
    $Global:NetworkResults
}