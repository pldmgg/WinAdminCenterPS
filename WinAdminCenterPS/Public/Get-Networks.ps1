<#
    .SYNOPSIS
        Gets the network ip configuration.
    
    .DESCRIPTION
        Gets the network ip configuration. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-Networks {
    Import-Module NetAdapter
    Import-Module NetTCPIP
    Import-Module DnsClient
    
    Set-StrictMode -Version 5.0
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Get all net information
    $netAdapter = Get-NetAdapter
    
    # conditions used to select the proper ip address for that object modeled after ibiza method.
    # We only want manual (set by user manually), dhcp (set up automatically with dhcp), or link (set from link address)
    # fe80 is the prefix for link local addresses, so that is the format want if the suffix origin is link
    # SkipAsSource -eq zero only grabs ip addresses with skipassource set to false so we only get the preffered ip address
    $ipAddress = Get-NetIPAddress | Where-Object {
        ($_.SuffixOrigin -eq 'Manual') -or
        ($_.SuffixOrigin -eq 'Dhcp') -or 
        (($_.SuffixOrigin -eq 'Link') -and (($_.IPAddress.StartsWith('fe80:')) -or ($_.IPAddress.StartsWith('2001:'))))
    }
    
    $netIPInterface = Get-NetIPInterface
    $netRoute = Get-NetRoute -PolicyStore ActiveStore
    $dnsServer = Get-DnsClientServerAddress
    
    # Load in relevant net information by name
    Foreach ($currentNetAdapter in $netAdapter) {
        $result = New-Object PSObject
    
        # Net Adapter information
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceAlias' -Value $currentNetAdapter.InterfaceAlias
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceIndex' -Value $currentNetAdapter.InterfaceIndex
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceDescription' -Value $currentNetAdapter.InterfaceDescription
        $result | Add-Member -MemberType NoteProperty -Name 'Status' -Value $currentNetAdapter.Status
        $result | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value $currentNetAdapter.MacAddress
        $result | Add-Member -MemberType NoteProperty -Name 'LinkSpeed' -Value $currentNetAdapter.LinkSpeed
    
        # Net IP Address information
        # Primary addresses are used for outgoing calls so SkipAsSource is false (0)
        # Should only return one if properly configured, but it is possible to set multiple, so collect all
        $primaryIPv6Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv6Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            $linkLocalArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv6Addresses) {
                if ($address -ne $null -and $address.IPAddress -ne $null -and $address.IPAddress.StartsWith('fe80')) {
                    $linkLocalArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
                else {
                    $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv6Address' -Value $ipArray
            $result | Add-Member -MemberType NoteProperty -Name 'LinkLocalIPv6Address' -Value $linkLocalArray
        }
    
        $primaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv4Address' -Value $ipArray
        }
    
        # Secondary addresses are not used for outgoing calls so SkipAsSource is true (1)
        # There will usually not be secondary addresses, but collect them just in case
        $secondaryIPv6Adresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv6Adresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv6Adresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv6Address' -Value $ipArray
        }
    
        $secondaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv4Address' -Value $ipArray
        }
    
        # Net IP Interface information
        $currentDhcpIPv4 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4')}
        if ($currentDhcpIPv4) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv4' -Value $currentDhcpIPv4.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $false
        }
    
        $currentDhcpIPv6 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6')}
        if ($currentDhcpIPv6) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv6' -Value $currentDhcpIPv6.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $false
        }
    
        # Net Route information
        # destination prefix for selected ipv6 address is always ::/0
        $currentIPv6DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '::/0')}
        if ($currentIPv6DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DefaultGateway' -Value $ipArray
        }
    
        # destination prefix for selected ipv4 address is always 0.0.0.0/0
        $currentIPv4DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '0.0.0.0/0')}
        if ($currentIPv4DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DefaultGateway' -Value $ipArray
        }
    
        # DNS information
        # dns server util code for ipv4 is 2
        $currentIPv4DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 2)}
        if ($currentIPv4DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DNSServer' -Value $ipArray
        }
    
        # dns server util code for ipv6 is 23
        $currentIPv6DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 23)}
        if ($currentIPv6DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DNSServer' -Value $ipArray
        }
    
        $adapterGuid = $currentNetAdapter.InterfaceGuid
        if ($adapterGuid) {
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapterGuid)"
          $ipv4Properties = Get-ItemProperty $regPath
          if ($ipv4Properties -and $ipv4Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $false
          }
    
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($adapterGuid)"
          $ipv6Properties = Get-ItemProperty $regPath
          if ($ipv6Properties -and $ipv6Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $false
          }
        }
    
        $result
    }
    
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUd8AUEw/naTXyjJfP+s73BYEk
# n8agggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDWwDr71nV8I3ChT
# dMm92cUlvb5iMA0GCSqGSIb3DQEBAQUABIIBAHFiNu+G7L7oRlQw2NCRbdK33p+u
# IjfwOCVmSc5vGmFrBIaABne9QN9rLPrk8mJH42YNbvTB7iwU9m/HEBufkwKEM1G/
# CBFSDCSqhd2uO7dFaYIwxNu3fbO3gR6cGaXTlnWFbKDr9CE5i3mLHZC9cHz1tySh
# 0MQnzKda3IGprqQIbma9wNtv0a3ckgN1AiW8tyRG3Frz8aXQdERyF80Zp/0sMDFD
# Iq3z0MqOT/zSUyn1SPNZJq+9sxfQPwS6csNr7Z2bz6o/tJtrpTrmLua77XKQtDgE
# EvHW8e3RdhSlMca4aOC63N8SuT3Es6BKo9/XYhKdjeDmuv71IU9CUIwYUK8=
# SIG # End signature block
