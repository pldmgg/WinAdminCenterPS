<#
    
    .SYNOPSIS
        Gets network adapter summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets network adapter summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
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

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUsmM8vRaEl+3l6hc1yqw1X0Ls
# yKugggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFmUzkJ/1jbQvneg
# gRjn/Q+aN4MVMA0GCSqGSIb3DQEBAQUABIIBAB/Ucg+BtEa9Q2XtgQJPI4+CmESv
# waRrffYxW1eV+gXC0FczosFhfSPyTn+E4vg4dpdg6JfkT0LJ+GFRNMgjNasb+fw/
# FBFsiLRrBwLK9SetMaN/qppsAKSfgQAhje4qSfZoYvx/E4daevMJyWmJLl7lvmT3
# 7yXilY5TQaX7d23B9l/cRnrpHCvfvfBNYP09JFZawsI2kirbtnj8T27P1ip/oJru
# dvslFqQvbqZitNtbC0glbhA0OBzL6CGc0T/O1eBIaWb335x60wOWNAmepeiplhmn
# Q4JFZ3ccx30apoESa1fnvcD6NTCu+pCiYlAwTwhBt3sLTi8OQHG0kJ8639A=
# SIG # End signature block
