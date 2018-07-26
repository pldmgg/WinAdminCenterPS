<#
    
    .SYNOPSIS
        Gets the recovery options for a specific service.
    
    .DESCRIPTION
        Gets the recovery options for a specific service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ServiceRecoveryOptions {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName
    )
    
    function Get-FailureAction {
        param (
            [Parameter(Mandatory = $true)] [int] $failureCode
        )
    
        $failureAction = switch ($failureCode) {
            0 { 'none' }
            1 { 'restart' }
            2 { 'reboot' }
            3 { 'run' }
            default {'none'}
        }
    
        $failureAction
    }
    
    
    $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
    $properties = Get-ItemProperty $regPath
    
    if ($properties -and $properties.FailureActions) {
        # value we get from the registry is a list of bytes that make up a list of little endian dword
        # each byte is in an integer representation from 0-255
    
        # convert each byte from an integer into hex, padding single digits to the left (ex: 191 -> BF, 2 -> 02)
        $properties.FailureActions = $properties.FailureActions | Foreach { [convert]::toString($_, 16).PadLeft(2, "0")}
    
        $dwords = New-Object System.Collections.ArrayList
        # break up list of bytes into dwords
        for ($i = 3; $i -lt $properties.FailureActions.length; $i += 4) {
            # make a dword that is a list of 4 bytes
            $dword = $properties.FailureActions[($i - 3)..$i]
            # reverse bytes in the dword to convert to big endian
            [array]::Reverse($dword)
            # concat list of bytes into one hex string then convert to a decimal
            $dwords.Add([convert]::toint32([string]::Concat($dword), 16)) > $null
        }
    
        # whole blob is type SERVICE_FAILURE_ACTIONS https://msdn.microsoft.com/en-ca/library/windows/desktop/ms685939(v=vs.85).aspx
        # resetPeriod is dwords 0 in seconds
        # dwords 5-6 is first action type SC_ACTION https://msdn.microsoft.com/en-ca/library/windows/desktop/ms685126(v=vs.85).aspx
        # dwords 7-8 is second
        # dwords 9-10 is last
    
        #convert dwords[0] from seconds to days
        $dwordslen = $dwords.Count
        if ($dwordslen -ge 0) {
            $resetFailCountIntervalDays = $dwords[0] / (60 * 60 * 24)
        }
    
        if ($dwordslen -ge 7) {
            $firstFailure = Get-FailureAction $dwords[5]
            if ($firstFailure -eq 'restart') {
                $restartIntervalMinutes = $dwords[6] / (1000 * 60)
            }
        }
    
        if ($dwordslen -ge 9) {
            $secondFailure = Get-FailureAction $dwords[7]
            if ($secondFailure -eq 'restart') {
                $restartIntervalMinutes = $dwords[8] / (1000 * 60)
            }
        }
    
        if ($dwordslen -ge 11) {
            $thirdFailure = Get-FailureAction $dwords[9]
            if ($thirdFailure -eq 'restart') {
                $restartIntervalMinutes = $dwords[10] / (1000 * 60)
            }
        }
    }
    
    # programs stored as "C:/Path/To Program" {command line params}
    if ($properties.FailureCommand) {
        # split up the properties but keep quoted command as one word
        $splitCommand = $properties.FailureCommand -Split ' +(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
        if ($splitCommand) {
            $splitLen = $splitCommand.Length
            if ($splitLen -gt 0) {
                # trim quotes from program path for display purposes
                $pathToProgram = $splitCommand[0].Replace("`"", "")
            }
    
            if ($splitLen -gt 1) {
                $parameters = $splitCommand[1..($splitLen - 1)] -Join ' '
            }
        }
    }
    
    $result = New-Object PSObject
    $result | Add-Member -MemberType NoteProperty -Name 'ResetFailCountInterval' -Value $resetFailCountIntervalDays
    $result | Add-Member -MemberType NoteProperty -Name 'RestartServiceInterval' -Value $restartIntervalMinutes
    $result | Add-Member -MemberType NoteProperty -Name 'FirstFailure' -Value $firstFailure
    $result | Add-Member -MemberType NoteProperty -Name 'SecondFailure' -Value $secondFailure
    $result | Add-Member -MemberType NoteProperty -Name 'ThirdFailure' -Value $thirdFailure
    $result | Add-Member -MemberType NoteProperty -Name 'PathToProgram' -Value $pathToProgram
    $result | Add-Member -MemberType NoteProperty -Name 'ProgramParameters' -Value $parameters
    $result
    
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUTziHMMxuSgd4onQ6sx2vytYN
# MqGgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFHQyuHThSLtSRHH6
# OAEAT5wzN1T7MA0GCSqGSIb3DQEBAQUABIIBALDJTGaGs1g1lAAX8PXlQWn19833
# pUdsEWjlyADap2dr0lXS1VvcGaMI52A/UZp5MUETkgg48KZtgtf1bCBUO0YpsZ4D
# 6+y3xX7dJOQTgqPtkVoq1cGEWhtx8vZjwoPw+07w5s9YJBIo0sznyf0hUDL9Uy+Y
# ruiODN/nkAxg/p0voMvZR7u2cAPoFcmLXCLSyOWM98son/b0zvXoLP8ufBXgokhf
# HO9Jg7xJwUrREZkWaZ+by6t83tol8yQsqMG9JrGzEnNb7FaFbrPqLwi6jY+bGjSC
# b+Rj+PvokeMf9hN55VnccHERJz9bG/xah1SfnpFwA/Mf6Z/5yHGL6A1SCi8=
# SIG # End signature block
