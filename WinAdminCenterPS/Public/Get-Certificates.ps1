<#
    
    .SYNOPSIS
        Script that enumerates all the certificates in the system.
    
    .DESCRIPTION
        Script that enumerates all the certificates in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-Certificates {
    param (
        [String]$path = "Cert:\",
        [int]$nearlyExpiredThresholdInDays = 60
    )
    
    <#############################################################################################
    
        Helper functions.
    
    #############################################################################################>
    
    <#
    .Synopsis
        Name: Get-ChildLeafRecurse
        Description: Recursively enumerates each scope and store in Cert:\ drive.
    
    .Parameters
        $pspath: The initial pspath to use for creating whole path to certificate store.
    
    .Returns
        The constructed ps-path object.
    #>
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    <#
    .Synopsis
        Name: Compute-PublicKey
        Description: Computes public key algorithm and public key parameters
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        A hashtable object of public key algorithm and public key parameters.
    #>
    function Compute-PublicKey
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $publicKeyInfo = @{}
    
        $publicKeyInfo["PublicKeyAlgorithm"] = ""
        $publicKeyInfo["PublicKeyParameters"] = ""
    
        if ($cert.PublicKey)
        {
            $publicKeyInfo["PublicKeyAlgorithm"] =  $cert.PublicKey.Oid.FriendlyName
            $publicKeyInfo["PublicKeyParameters"] = $cert.PublicKey.EncodedParameters.Format($true)
        }
    
        $publicKeyInfo
    }
    
    <#
    .Synopsis
        Name: Compute-SignatureAlgorithm
        Description: Computes signature algorithm out of original certificate object.
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        The signature algorithm friendly name.
    #>
    function Compute-SignatureAlgorithm
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $signatureAlgorithm = [System.String]::Empty
    
        if ($cert.SignatureAlgorithm)
        {
            $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
        }
    
        $signatureAlgorithm
    }
    
    <#
    .Synopsis
        Name: Compute-PrivateKeyStatus
        Description: Computes private key exportable status.
    .Parameters
        $hasPrivateKey: A flag indicating certificate has a private key or not.
        $canExportPrivateKey: A flag indicating whether certificate can export a private key.
    
    .Returns
        Enum values "Exported" or "NotExported"
    #>
    function Compute-PrivateKeyStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $hasPrivateKey,
    
            [Parameter(Mandatory = $true)]
            [bool]
            $canExportPrivateKey
        )
    
        if (-not ($hasPrivateKey))
        {
            $privateKeystatus = "None"
        }
        else
        {
            if ($canExportPrivateKey)
            {
                $privateKeystatus = "Exportable"
            }
            else
            {
                $privateKeystatus = "NotExportable"
            }
        }
    
        $privateKeystatus
    }
    
    <#
    .Synopsis
        Name: Compute-ExpirationStatus
        Description: Computes expiration status based on notAfter date.
    .Parameters
        $notAfter: A date object refering to certificate expiry date.
    
    .Returns
        Enum values "Expired", "NearlyExpired" and "Healthy"
    #>
    function Compute-ExpirationStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [DateTime]$notAfter
        )
    
        if ([DateTime]::Now -gt $notAfter)
        {
           $expirationStatus = "Expired"
        }
        else
        {
           $nearlyExpired = [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays);
    
           if ($nearlyExpired -ge $notAfter)
           {
              $expirationStatus = "NearlyExpired"
           }
           else
           {
              $expirationStatus = "Healthy"
           }
        }
    
        $expirationStatus
    }
    
    <#
    .Synopsis
        Name: Compute-ArchivedStatus
        Description: Computes archived status of certificate.
    .Parameters
        $archived: A flag to represent archived status.
    
    .Returns
        Enum values "Archived" and "NotArchived"
    #>
    function Compute-ArchivedStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $archived
        )
    
        if ($archived)
        {
            $archivedStatus = "Archived"
        }
        else
        {
            $archivedStatus = "NotArchived"
        }
    
        $archivedStatus
    }
    
    <#
    .Synopsis
        Name: Compute-IssuedTo
        Description: Computes issued to field out of the certificate subject.
    .Parameters
        $subject: Full subject string of the certificate.
    
    .Returns
        Issued To authority name.
    #>
    function Compute-IssuedTo
    {
        param (
            [String]
            $subject
        )
    
        $issuedTo = [String]::Empty
    
        $issuedToRegex = "CN=(?<issuedTo>[^,?]+)"
        $matched = $subject -match $issuedToRegex
    
        if ($matched -and $Matches)
        {
           $issuedTo = $Matches["issuedTo"]
        }
    
        $issuedTo
    }
    
    <#
    .Synopsis
        Name: Compute-IssuerName
        Description: Computes issuer name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The Issuer authority name.
    #>
    function Compute-IssuerName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $issuerName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    
        $issuerName
    }
    
    <#
    .Synopsis
        Name: Compute-CertificateName
        Description: Computes certificate name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The certificate name.
    #>
    function Compute-CertificateName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (!$certificateName) {
            $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        }
    
        $certificateName
    }
    
    <#
    .Synopsis
        Name: Compute-Store
        Description: Computes certificate store name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate store name.
    #>
    function Compute-Store
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Scope
        Description: Computes certificate scope/location name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate scope/location name.
    #>
    function Compute-Scope
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[1].Split(':')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Path
        Description: Computes certificate path. E.g. CurrentUser\My\<thumbprint>
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate path.
    #>
    function Compute-Path
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split(':')[2]
    }
    
    
    <#
    .Synopsis
        Name: EnhancedKeyUsage-List
        Description: Enhanced KeyUsage
    .Parameters
        $cert: The original cert object.
    
    .Returns
        Enhanced Key Usage.
    #>
    function EnhancedKeyUsage-List
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $usageString = ''
        foreach ( $usage in $cert.EnhancedKeyUsageList){
           $usageString = $usageString + $usage.FriendlyName + ' ' + $usage.ObjectId + "`n"
        }
    
        $usageString
    }
    
    <#
    .Synopsis
        Name: Compute-Template
        Description: Compute template infomation of a certificate
        $certObject: The original certificate object.
    
    .Returns
        The certificate template if there is one otherwise empty string
    #>
    function Compute-Template
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $template = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if ($template) {
            $name = $template.Format(1).split('(')[0]
            if ($name) {
                $name -replace "Template="
            }
            else {
                ''
            }
        }
        else {
            ''
        }
    }
    
    <#
    .Synopsis
        Name: Extract-CertInfo
        Description: Extracts certificate info by decoding different field and create a custom object.
    .Parameters
        $certObject: The original certificate object.
    
    .Returns
        The custom object for certificate.
    #>
    function Extract-CertInfo
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $certObject
        )
    
        $certInfo = @{}
    
        $certInfo["Archived"] = $(Compute-ArchivedStatus $certObject.Archived)
        $certInfo["CertificateName"] = $(Compute-CertificateName $certObject)
    
        $certInfo["EnhancedKeyUsage"] = $(EnhancedKeyUsage-List $certObject) #new
        $certInfo["FriendlyName"] = $certObject.FriendlyName
        $certInfo["IssuerName"] = $(Compute-IssuerName $certObject)
        $certInfo["IssuedTo"] = $(Compute-IssuedTo $certObject.Subject)
        $certInfo["Issuer"] = $certObject.Issuer #new
    
        $certInfo["NotAfter"] = $certObject.NotAfter
        $certInfo["NotBefore"] = $certObject.NotBefore
    
        $certInfo["Path"] = $(Compute-Path  $certObject.PsPath)
        $certInfo["PrivateKey"] =  $(Compute-PrivateKeyStatus -hasPrivateKey $certObject.CalculatedHasPrivateKey -canExportPrivateKey  $certObject.CanExportPrivateKey)
        $publicKeyInfo = $(Compute-PublicKey $certObject)
        $certInfo["PublicKey"] = $publicKeyInfo.PublicKeyAlgorithm
        $certInfo["PublicKeyParameters"] = $publicKeyInfo.PublicKeyParameters
    
        $certInfo["Scope"] = $(Compute-Scope  $certObject.PsPath)
        $certInfo["Store"] = $(Compute-Store  $certObject.PsPath)
        $certInfo["SerialNumber"] = $certObject.SerialNumber
        $certInfo["Subject"] = $certObject.Subject
        $certInfo["Status"] =  $(Compute-ExpirationStatus $certObject.NotAfter)
        $certInfo["SignatureAlgorithm"] = $(Compute-SignatureAlgorithm $certObject)
    
        $certInfo["Thumbprint"] = $certObject.Thumbprint
        $certInfo["Version"] = $certObject.Version
    
        $certInfo["Template"] = $(Compute-Template $certObject)
    
        $certInfo
    }
    
    
    <#############################################################################################
    
        Main script.
    
    #############################################################################################>
    
    
    $certificates =  @()
    
    Get-ChildLeafRecurse $path | foreach {
        $cert = $_
        $cert | Add-Member -Force -NotePropertyName "CalculatedHasPrivateKey" -NotePropertyValue $_.HasPrivateKey
        $exportable = $false
    
        if ($cert.HasPrivateKey)
        {
            [System.Security.Cryptography.CspParameters] $cspParams = new-object System.Security.Cryptography.CspParameters
            $contextField = $cert.GetType().GetField("m_safeCertContext", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
            $privateKeyMethod = $cert.GetType().GetMethod("GetPrivateKeyInfo", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
            if ($contextField -and $privateKeyMethod) {
            $contextValue = $contextField.GetValue($cert)
            $privateKeyInfoAvailable = $privateKeyMethod.Invoke($cert, @($ContextValue, $cspParams))
            if ($privateKeyInfoAvailable)
            {
                $PrivateKeyCount++
                $csp = new-object System.Security.Cryptography.CspKeyContainerInfo -ArgumentList @($cspParams)
                if ($csp.Exportable)
                {
                    $exportable = $true
                }
            }
            }
            else
            {
                    $exportable = $true
            }
        }
    
        $cert | Add-Member -Force -NotePropertyName "CanExportPrivateKey" -NotePropertyValue $exportable
    
        $certificates += Extract-CertInfo $cert
    
        }
    
    $certificates
    
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwBmimWdN8iI1b0dZ6WZCIYx+
# tNqgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFOnKuSSsiRNNBkCJ
# IaCGXmuq2NliMA0GCSqGSIb3DQEBAQUABIIBAEFFajKfKCecKxGBjvszbyx9cSJi
# CXyDuw+iKfrrQm5qMp2WanFSpAall0b2A2dw7d/jrJQ1JeCDCHMj6WPeWUeIh87Q
# tzS5wFYMJXqrNNNU7UMJPcOCRj2BuEQ97JzTb1RVjMrMxv/7uICweE9+MzRx3InF
# R7q9iu7UGTxIvlu+VPiHmL9kOG95Scuw2ImajglEZW0Q4mmjn2f/oZlFrntJlDhU
# qWQy9Uc65IjyyVEVbaa7VzGtUoE0/YWPHM+MmhBwLqL9MpiyyB5OzHxvP/2njUFS
# gK6U7Y95koq1c7zkKUHweqrSecDgkUc7Xg3e6SRxSqdFe8BfJNcHAmoLmmU=
# SIG # End signature block
