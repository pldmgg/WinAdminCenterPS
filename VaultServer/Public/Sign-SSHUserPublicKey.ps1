<#
    .SYNOPSIS
        This function signs an SSH Client/User Public Key (for example, "$HOME\.ssh\id_rsa.pub") resulting
        in a Public Certificate (for example, "$HOME\.ssh\id_rsa-cert.pub"). This Public Certificate can
        then be used for Public Key Certificate SSH Authentication.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultSSHClientSigningUrl
        This parameter is MANDATORY.

        This parameter takes a string that represents the Vault Server REST API endpoint responsible
        for signing Client/User SSH Keys. The Url should be something like:
            https://vaultserver.zero.lab:8200/v1/ssh-client-signer/sign/clientrole

    .PARAMETER VaultAuthToken
        This parameter is MANDATORY.

        This parameter takes a string that represents a Vault Authentication Token that has
        permission to request SSH User/Client Key Signing via the Vault Server REST API.

    .PARAMETER AuthorizedUserPrincipals
        This parameter is MANDATORY.

        This parameter takes a string or array of strings that represent the User or Users that will
        be using the Public Key Certificate to SSH into remote machines.

        Local User Accounts MUST be in the format <UserName>@<LocalHostComputerName> and
        Domain User Accounts MUST be in the format <UserName>@<DomainPrefix>. (To clarify DomainPrefix: if your
        domain is, for example, 'zero.lab', your DomainPrefix would be 'zero').

    .PARAMETER PathToSSHUserPublicKeyFile
        This parameter is MANDATORY.

        This parameter takes a string that represents the full path to the SSH Public Key that you would like
        the Vault Server to sign. Example: "$HOME\.ssh\id_rsa.pub"

    .PARAMETER PathToSSHUserPrivateKeyFile
        This parameter is OPTIONAL, but becomes MANDATORY if you want to add the signed Public Key Certificate to
        the ssh-agent service.

        This parameter takes a string that represents a full path to the SSH User/Client private key file.

    .PARAMETER AddToSSHAgent
        This parameter is OPTIONAL.

        This parameter is a switch. If used, the signed Public Key Certificate will be added to the ssh-agent service. 

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $SplatParams = @{
            VaultSSHClientSigningUrl    = $VaultSSHClientSigningUrl
            VaultAuthToken              = $ZeroAdminToken
            AuthorizedUserPrincipals    = @("zeroadmin@zero")
            PathToSSHUserPublicKeyFile  = "$HOME\.ssh\zeroadmin_id_rsa.pub"
            PathToSSHUserPrivateKeyFile = "$HOME\.ssh\zeroadmin_id_rsa"
            AddToSSHAgent               = $True
        }
        PS C:\Users\zeroadmin> Sign-SSHUserPublicKey @SplatParams
        
#>
function Sign-SSHUserPublicKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [string]$VaultSSHClientSigningUrl, # Should be something like "http://192.168.2.12:8200/v1/ssh-client-signer/sign/clientrole"

        [Parameter(Mandatory=$True)]
        [string]$VaultAuthToken, # Should be something like 'myroot' or '434f37ca-89ae-9073-8783-087c268fd46f'

        [Parameter(Mandatory=$True)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$AuthorizedUserPrincipals, # Should be in format <User>@<HostNameOrDomainPrefix> - and can be an array of strings

        [Parameter(Mandatory=$True)]
        [ValidatePattern("\.pub")]
        [string]$PathToSSHUserPublicKeyFile,

        [Parameter(Mandatory=$False)]
        [string]$PathToSSHUserPrivateKeyFile,

        [Parameter(Mandatory=$False)]
        [switch]$AddToSSHAgent
    )

    if (!$(Test-Path $PathToSSHUserPublicKeyFile)) {
        Write-Error "The path '$PathToSSHUserPublicKeyFile' was not found! Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($PathToSSHUserPrivateKeyFile) {
        $CorrespondingPrivateKeyPath = $PathToSSHUserPrivateKeyFile
    }
    else {
        $CorrespondingPrivateKeyPath = $PathToSSHUserPublicKeyFile -replace "\.pub",""
    }

    if (!$(Test-Path $CorrespondingPrivateKeyPath)) {
        Write-Error "Unable to find expected path to corresponding private key, i.e. '$CorrespondingPrivateKeyPath'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    $SignedPubKeyCertFilePath = $PathToSSHUserPublicKeyFile -replace "\.pub","-cert.pub"
    
    # Check to make sure the user private key isn't password protected. If it is, things break
    # with current Windows OpenSSH implementation
    try {
        $ValidateSSHPrivateKeyResult = Validate-SSHPrivateKey -PathToPrivateKeyFile $CorrespondingPrivateKeyPath -ErrorAction Stop
        if (!$ValidateSSHPrivateKeyResult) {throw "There was a problem with the Validate-SSHPrivateKey function! Halting!"}

        if (!$ValidateSSHPrivateKeyResult.ValidSSHPrivateKeyFormat) {
            throw "'$CorrespondingPrivateKeyPath' is not in a valid format! Double check with: ssh-keygen -y -f `"$CorrespondingPrivateKeyPath`""
        }
        if ($ValidateSSHPrivateKeyResult.PasswordProtected) {
            throw "'$CorrespondingPrivateKeyPath' is password protected! This breaks the current implementation of OpenSSH on Windows. Halting!"
        }
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Make sure $VaultSSHClientSigningUrl is a valid Url
    try {
        $UriObject = [uri]$VaultSSHClientSigningUrl
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    if (![bool]$($UriObject.Scheme -match "http")) {
        Write-Error "'$VaultSSHClientSigningUrl' does not appear to be a URL! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # If $VaultSSHClientSigningUrl ends in '/', remove it
    if ($VaultSSHClientSigningUrl[-1] -eq "/") {
        $VaultSSHClientSigningUrl = $VaultSSHClientSigningUrl.Substring(0,$VaultSSHClientSigningUrl.Length-1)
    }

    ##### BEGIN Main Body #####

    # HTTP API Request
    # The below removes 'comment' text from the Host Public key because sometimes it can cause problems
    # with the below json
    $PubKeyContent = $($(Get-Content $PathToSSHUserPublicKeyFile) -split "[\s]")[0..1] -join " "
    $ValidPrincipalsCommaSeparated = $AuthorizedUserPrincipals -join ','
    # In the below JSON, <HostNameOrDomainPre> - Use the HostName if user is a Local Account and the DomainPre if the user
    # is a Domain Account
    $jsonRequest = @"
{
    "cert_type": "user",
    "valid_principals": "$ValidPrincipalsCommaSeparated",
    "extension": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    },
    "public_key": "$PubKeyContent"
}
"@
    $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json | ConvertTo-Json -Compress

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }
    $IWRSplatParams = @{
        Uri         = $VaultSSHClientSigningUrl
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }

    $SignedSSHClientPubKeyCertResponse = Invoke-WebRequest @IWRSplatParams
    Set-Content -Value $($SignedSSHClientPubKeyCertResponse.Content | ConvertFrom-Json).data.signed_key.Trim() -Path $SignedPubKeyCertFilePath

    if ($AddToSSHAgent) {
        # Push/Pop-Location probably aren't necessary...but just in case...
        Push-Location $($CorrespondingPrivateKeyPath | Split-Path -Parent)
        ssh-add "$CorrespondingPrivateKeyPath"
        Pop-Location
        $AddedToSSHAgent = $True
    }

    $Output = @{
        SignedCertFile      = $(Get-Item $SignedPubKeyCertFilePath)
    }
    if ($AddedToSSHAgent) {
        $Output.Add("AddedToSSHAgent",$True)
    }

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUdUdTS9dI3akclciEfi1L0AYf
# uDOgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCr0Xfak/7m/7ObY
# azaTyQ7fZivfMA0GCSqGSIb3DQEBAQUABIIBALCdnkqyKS14Ul7q8AYKCwH8bol1
# ArTQzPYMna94OM8kWV36gs904dmVowyBkRrVGtQauxHwDJRpZ9xoRFAlvqeMcVe1
# UYBZgDOhlZsGeuiXmExFckZeeXiOvV9sPTIr+OeXF4LQPwXLzX1+BYoLxbAy/c+3
# KIllvVsVtXuZSUN9Bwwfm6bC0skr5zkI4vIetJSkxPfFzul42nEXcdhfRSZJTC/e
# EVrXNPJNMscBGsUzd9iafX+bFfMHjwe+pdNMj3vJ6/NMnTtbyKxoD94xHRsAQPGY
# fM/E+2qflWmtXLTNEaZH7YPCgd9WFuEDFxJqJ3m/F+rw0mC3Q5e9Ci0t7bI=
# SIG # End signature block
