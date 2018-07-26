<#
    
    .SYNOPSIS
        Renew Certificate
    
    .DESCRIPTION
        Renew Certificate

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Update-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $username,
        [Parameter(Mandatory = $true)]
        [String]
        $password,
        [Parameter(Mandatory = $true)]
        [Boolean]
        $sameKey,
        [Parameter(Mandatory = $true)]
        [Boolean]
        $isRenew,
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
        [Parameter(Mandatory = $true)]
        [String]
        $RemoteComputer
    )
    
    $pw = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object PSCredential($username, $pw)
    
    Invoke-Command -Computername $RemoteComputer -ScriptBlock {
        param($Path, $isRenew, $sameKey)
        $global:result = ""
    
        $Cert = Get-Item -Path $Path
    
        $Template = $Cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if (!$Template) {
            $global:result = "NoTemplate"
            $global:result
            exit
        }
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379399(v=vs.85).aspx
        #X509CertificateEnrollmentContext
        $ContextUser                      = 0x1
        $ContextMachine                   = 0x2
        $ContextAdministratorForceMachine = 0x3
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        #EncodingType
        $XCN_CRYPT_STRING_BASE64HEADER        = 0
        $XCN_CRYPT_STRING_BASE64              = 0x1
        $XCN_CRYPT_STRING_BINARY              = 0x2
        $XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3
        $XCN_CRYPT_STRING_HEX                 = 0x4
        $XCN_CRYPT_STRING_HEXASCII            = 0x5
        $XCN_CRYPT_STRING_BASE64_ANY          = 0x6
        $XCN_CRYPT_STRING_ANY                 = 0x7
        $XCN_CRYPT_STRING_HEX_ANY             = 0x8
        $XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9
        $XCN_CRYPT_STRING_HEXADDR             = 0xa
        $XCN_CRYPT_STRING_HEXASCIIADDR        = 0xb
        $XCN_CRYPT_STRING_HEXRAW              = 0xc
        $XCN_CRYPT_STRING_NOCRLF              = 0x40000000
        $XCN_CRYPT_STRING_NOCR                = 0x80000000
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379430(v=vs.85).aspx
        #X509RequestInheritOptions
        $InheritDefault                = 0x00000000
        $InheritNewDefaultKey          = 0x00000001
        $InheritNewSimilarKey          = 0x00000002
        $InheritPrivateKey             = 0x00000003
        $InheritPublicKey              = 0x00000004
        $InheritKeyMask                = 0x0000000f
        $InheritNone                   = 0x00000010
        $InheritRenewalCertificateFlag = 0x00000020
        $InheritTemplateFlag           = 0x00000040
        $InheritSubjectFlag            = 0x00000080
        $InheritExtensionsFlag         = 0x00000100
        $InheritSubjectAltNameFlag     = 0x00000200
        $InheritValidityPeriodFlag     = 0x00000400
        $X509RequestInheritOptions = $InheritTemplateFlag
        if ($isRenew) {
            $X509RequestInheritOptions += $InheritRenewalCertificateFlag
        }
        if ($sameKey) {
            $X509RequestInheritOptions += $InheritPrivateKey
        }
    
        $Context = $ContextAdministratorForceMachine
    
        $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        $PKCS10.Silent=$true
    
        $PKCS10.InitializeFromCertificate($Context,[System.Convert]::ToBase64String($Cert.RawData), $XCN_CRYPT_STRING_BASE64, $X509RequestInheritOptions)
        $PKCS10.AlternateSignatureAlgorithm=$false
        $PKCS10.SmimeCapabilities=$false
        $PKCS10.SuppressDefaults=$true
        $PKCS10.Encode()
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa377809(v=vs.85).aspx
        $Enroll = New-Object -ComObject X509Enrollment.CX509Enrollment
        $Enroll.InitializeFromRequest($PKCS10)
        $Enroll.Enroll()
    
        if ($Error.Count -eq 0) {
            $Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
            $Cert.Import([System.Convert]::FromBase64String($Enroll.Certificate(1)))
            $global:result = $Cert.Thumbprint
        }
    
        $global:result
    
    } -Credential $credential -ArgumentList $Path, $isRenew, $sameKey
    
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUe68jNFxItNO1S6fO+vWjkIYw
# x22gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFDaKNja4ELxHMkDY
# zozIlxszZnSzMA0GCSqGSIb3DQEBAQUABIIBAFbtDApl1UtGk9m4O8qCNzEkkXet
# oplBlAhkghNtl3Y4wDAwI7eYp5+KimEXHwr1mRyEZk9dBMwHQ2R9PC5CzAR/6aZW
# +qzdMH8hpORVLddpSPUc0gTanH9kbEiPLDNtbnnzyP4woRsJlaGSYUZ40pE/E6LC
# UG0jUg8tgedCnNu9Fpa6qQT/L02kWaBqUV2JdrKqamWypCgSaKXNQBlOObkEpOUx
# a91bosE5aIBXGMCcr1b9XPXzmTXqOC+VvYk4paTAIA6BH5DCy6ZAa8HCMn5IwFqd
# jngVg9GBk/VLD+yJBlCeb0zwa5uIGUK8yRSGOI/LAHtgIOU8342zflnrgBI=
# SIG # End signature block
