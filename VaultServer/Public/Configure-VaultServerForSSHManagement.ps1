<#
    .SYNOPSIS
        This function uses the Hashicorp Vault Server's REST API to configure the Vault Server for
        SSH Public Key Authentication and Management.

        The following actions are performed on teh Vault Server (via the REST API):
            - The Vault SSH User/Client Key Signer is enabled
            - A Certificate Authority (CA) for the SSH User/Client Key Signer is created
            - The Vault SSH Host/Machine Key Signer is enabled
            - A Certificate Authority (CA) for the SSH Host/Machine Key Signer is created
            - The Vault the SSH User/Client Signer Role Endpoint is configured
            - The Vault the SSH Host/Machine Signer Role Endpoint is configured

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER VaultServerBaseUri
        This parameter is MANDATORY.

        This parameter takes a string that represents Base Uri for the Vault Server REST API. It should be
        something like:
            "https://vaultserver.zero.lab:8200/v1"

    .PARAMETER DomainCredentialsWithAdminAccessToVault
        This parameter is OPTIONAL. However, either this parameter or the -VaultAuthToken parameter is REQUIRED.

        This parameter takes a PSCredential. Assuming that LDAP Authenitcation is already enabled and configured
        onthe Vault Server, create a PSCredential that is a member of the "VaultAdmins" Security Group (or
        equivalent) in LDAP.
            $Creds = [pscredential]::new("zero\zeroadmin",$(Read-Host "Please Enter the Password for 'zero\zeroadmin'" -AsSecureString))

    .PARAMETER VaultAuthToken
        This parameter is OPTIONAL. However, either this parameter or the -DomainCredentialsWithAdminAccessToVault
        parameter is REQUIRED.

        This parameter takes a string that represents a Vault Authentication Token that has privileges to make
        configuration changes to the Vault Server.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -

        PS C:\Users\zeroadmin> $ConfigureVaultSSHMgmt = Configure-VaultServerForSSHManagement -VaultServerBaseUri $VaultServerBaseUri -VaultAuthToken $ZeroAdminToken
        
#>
function Configure-VaultServerForSSHManagement {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidatePattern("\/v1$")]
        [string]$VaultServerBaseUri,

        [Parameter(Mandatory=$False)]
        [pscredential]$DomainCredentialsWithAdminAccessToVault,

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken
    )

    if ($(!$VaultAuthToken -and !$DomainCredentialsWithAccessToVault) -or $($VaultAuthToken -and $DomainCredentialsWithAdminAccessToVault)) {
        Write-Error "The $($MyInvocation.MyCommand.Name) function requires one (no more, no less) of the following parameters: [-DomainCredentialsWithAdminAccessToVault, -VaultAuthToken] Halting!"
        $global:FunctionResult = "1"
        return
    }

    if ($DomainCredentialsWithAdminAccessToVault) {
        $GetVaultLoginSplatParams = @{
            VaultServerBaseUri                          = $VaultServerBaseUri
            DomainCredentialsWithAdminAccessToVault     = $DomainCredentialsWithAdminAccessToVault
            ErrorAction                                 = "Stop"
        }

        try {
            $VaultAuthToken = Get-VaultLogin @GetVaultLoginSplatParams
            if (!$VaultAuthToken) {throw "The Get-VaultLogin function failed! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            return
        }
    }

    $HeadersParameters = @{
        "X-Vault-Token" = $VaultAuthToken
    }

    # Create $Output HashTable to add results as we go...
    $Output = [ordered]@{}

    # We'll be configuring a Certificate Authority for ssh client key signing, and a Certificate Authority for
    # ssh machine host key signing
    
    ##### ENABLE SSH CLIENT CERT SIGNING #####

    # Vault CmdLine equivalent of below HTTP Request -
    #     vault secrets enable -path=ssh-client-signer ssh
    $jsonRequest = @"
{
    "type": "ssh",
    "description": "SSH Client Signer"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault SSH Client Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-client-signer"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableSSHClientSigner = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHClientSignerEnabledPrep = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHClientSignerEnabledPrep) {
        Write-Error "There was a problem confirming that the Vault SSH Client Signer was enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $ConfirmSSHClientSignerEnabled = $($ConfirmSSHClientSignerEnabledPrep.data | Get-Member -MemberType Properties).Name -contains "ssh-client-signer/"
    $Output.Add("SSHClientSignerEnabled",$ConfirmSSHClientSignerEnabled)

    # Create A Certificate Authority dedicated to SSH Client Certs and Generate a Public/Private Key Pair for the CA
    # Vault CmdLine equivalent of below HTTP Request -
    #     vault write ssh-client-signer/config/ca generate_signing_key=true
    $jsonRequest = @"
{
    "generate_signing_key": true
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the SSH Client Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-client-signer/config/ca"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $CreateSSHClientCA = Invoke-RestMethod @IWRSplatParams
    $SSHClientCAPublicKey = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-client-signer/public_key" -Method Get
    if (!$SSHClientCAPublicKey) {
        Write-Error "There was a problem getting the Public Key of the SSH Client Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHClientSignerCAPublicKey",$SSHClientCAPublicKey)


    ##### ENABLE SSH HOST CERT SIGNING #####

    # Vault CmdLine equivalent of below HTTP Request -
    # vault secrets enable -path=ssh-host-signer ssh
    $jsonRequest = @"
{
    "type": "ssh",
    "description": "SSH Host Signer"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for enabling the Vault SSH Host Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-host-signer"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $EnableSSHHostSigner = Invoke-WebRequest @IWRSplatParams
    $ConfirmSSHHostSignerEnabledPrep = Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHHostSignerEnabledPrep) {
        Write-Error "There was a problem confirming that the Vault SSH Host Signer was enabled! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $ConfirmSSHHostSignerEnabled = $($ConfirmSSHHostSignerEnabledPrep.data | Get-Member -MemberType Properties).Name -contains "ssh-host-signer/"
    $Output.Add("SSHHostSignerEnabled",$ConfirmSSHHostSignerEnabled)

    # Create A Certificate Authority dedicated to SSH Host Certs and Generate a Public/Private Key Pair for the CA
    #     vault write ssh-host-signer/config/ca generate_signing_key=true
    $jsonRequest = @"
{
    "generate_signing_key": true
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for creating the SSH Host Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-host-signer/config/ca"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $CreateSSHHostCA = Invoke-RestMethod @IWRSplatParams
    $SSHHostCAPublicKey = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-host-signer/public_key" -Method Get
    if (!$SSHHostCAPublicKey) {
        Write-Error "There was a problem getting the Public Key of the SSH Host Signer Certificate Authority! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerCAPublicKey",$SSHHostCAPublicKey)

    # Extend Host Cert TTL to 10 years
    #     vault secrets tune -max-lease-ttl=87600h ssh-host-signer
    $jsonRequest = @"
{
    "max_lease_ttl": "87600h"
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for Tuning the SSH Host Signer! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/sys/mounts/ssh-host-signer/tune"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $TuneHostSSHCertValidityPeriod = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHHostSignerTune = $(Invoke-RestMethod -Uri "$VaultServerBaseUri/sys/mounts" -Headers $HeadersParameters -Method Get).'ssh-host-signer/'.config
    if ($ConfirmSSHHostSignerTune.max_lease_ttl -ne 315360000) {
        Write-Error "There was a problem tuning the Vault Server to set max_lease_ttl for signed host ssh keys for 10 years. Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerTuning",$ConfirmSSHHostSignerTune)


    ##### Configure the SSH Client Signer Role #####
    $DefaultUser = $($(whoami) -split "\\")[-1]
    
    $jsonRequest = @"
{
    "key_type": "ca",
    "default_user": "$DefaultUser",
    "allow_user_certificates": true,
    "allowed_users": "*",
    "ttl": "24h",
    "default_extensions": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for configuring the SSH Client Signer Role! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-client-signer/roles/clientrole"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $SetSSHClientRole = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHClientRole = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-client-signer/roles/clientrole" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHClientRole.data) {
        Write-Error "There was a problem creating the the ssh-client-signer Role 'clientrole'! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHClientSignerRole",$ConfirmSSHClientRole)

    ##### Configure the SSH Host Signer Role #####
    $jsonRequest = @"
{
    "key_type": "ca",
    "cert_type": "host",
    "allow_host_certificates": "true",
    "allowed_domains": "*",
    "allow_subdomains": "true",
    "ttl": "87600h",
    "default_extensions": {
        "permit-pty": "",
        "permit-agent-forwarding": ""
    }
}
"@
    try {
        # Validate JSON
        $JsonRequestAsSingleLineString = $jsonRequest | ConvertFrom-Json -EA Stop | ConvertTo-Json -Compress -EA Stop
    }
    catch {
        Write-Error "There was a problem with the JSON for configuring the SSH Host Signer Role! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $IWRSplatParams = @{
        Uri         = "$VaultServerBaseUri/ssh-host-signer/roles/hostrole"
        Headers     = $HeadersParameters
        Body        = $JsonRequestAsSingleLineString
        Method      = "Post"
    }
    $SetSSHHostRole = Invoke-RestMethod @IWRSplatParams
    $ConfirmSSHHostRole = Invoke-RestMethod -Uri "$VaultServerBaseUri/ssh-host-signer/roles/hostrole" -Headers $HeadersParameters -Method Get
    if (!$ConfirmSSHHostRole.data) {
        Write-Error "There was a problem creating the the ssh-host-signer Role 'hostrole'! Halting!"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        $global:FunctionResult = "1"
        return
    }
    $Output.Add("SSHHostSignerRole",$ConfirmSSHHostRole)

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU4h7V4Ld7qXuDaOdHVMIYbX+3
# tZygggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFA8tUU+/w4KbT8F4
# r7/48dMiqaFBMA0GCSqGSIb3DQEBAQUABIIBAHNjC6hHpMlFbg3h2jkplUDdcLYS
# e4bk0292N1p++2wL8lQD1H+TppZXVzvnPlQS3JuyUnNa2JoQrEOYQU7k9c+dg98s
# AB7Xhtd5GXMkx9mj4Ip4AovBVPwAquRC/yzO+t/BdJVNm5mTfPhyXQ095Nd+E0wz
# sI9arCD1jS9jQ+Rgib7iNQGmApA73121aCh3VAG/fzzydlZfbKjvlv3n6crEbutd
# ZLLW6jwbpEYrn8mI8mZkQE/fvY/lePYbDRoBKKhSfnV/yzTJR/wn4+ncvil6zueO
# vqgiSpuMSpBrsNt77x4GD0BtcwyGll3fnJC+C7+l2+L2/xNIME02tJmfQcs=
# SIG # End signature block
