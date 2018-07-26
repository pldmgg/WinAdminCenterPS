[CmdletBinding(DefaultParameterSetName = 'task')]
Param (
    [Parameter(
        Mandatory = $False,
        ParameterSetName = 'task',
        Position = 0
    )]
    [string[]]$Task = 'Default',

    [Parameter(Mandatory = $False)]
    [string]$CertFileForSignature,

    [Parameter(Mandatory = $False)]
    [ValidateNotNullorEmpty()]
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert,

    [Parameter(Mandatory = $False)]
    [pscredential]$AdminUserCreds,

    [Parameter(
        Mandatory = $False,
        ParameterSetName = 'help'
    )]
    [switch]$Help,

    [Parameter(Mandatory = $False)]
    [switch]$AppVeyorContext
)

# Workflow is build.ps1 -> psake.ps1 -> *Tests.ps1

##### BEGIN Prepare For Build #####

$ElevationCheck = [System.Security.Principal.WindowsPrincipal]::new([System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (!$ElevationCheck) {
    Write-Error "You must run the build.ps1 as an Administrator (i.e. elevated PowerShell Session)! Halting!"
    $global:FunctionResult = "1"
    return
}

if ($AdminUserCreds) {
    # Make sure $AdminUserCreds.UserName format is <Domain>\<User> and <LocalHostName>\<User>
    if ($AdminUserCreds.UserName -notmatch "[\w]+\\[\w]+") {
        Write-Error "The UserName provided in the PSCredential -AdminUserCreds is not in the correct format! Please create the PSCredential with a UserName in the format <Domain>\<User> or <LocalHostName>\<User>. Halting!"
        $global:FunctionResult = "1"
        return
    }
}

if ($CertFileForSignature -and !$Cert) {
    if (!$(Test-Path $CertFileForSignature)) {
        Write-Error "Unable to find the Certificate specified to be used for Code Signing! Halting!"
        $global:FunctionResult = "1"
        return
    }

    try {
        $Cert = Get-PfxCertificate $CertFileForSignature -ErrorAction Stop
        if (!$Cert) {throw "There was a prblem with the Get-PfcCertificate cmdlet! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }
}

if ($Cert) {
    # Make sure the Cert is good for Code Signing
    if ($Cert.EnhancedKeyUsageList.ObjectId -notcontains "1.3.6.1.5.5.7.3.3") {
        $CNOfCert = $($($Cert.Subject -split ",")[0] -replace "CN=","").Trim()
        Write-Error "The provided Certificate $CNOfCert says that it should be sued for $($Cert.EnhancedKeyUsageList.FriendlyName -join ','), NOT 'Code Signing'! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Make sure our ProtoHelpers are signed before we do anything else, otherwise we won't be able to use them
    $HelperFilestoSign = Get-ChildItem $(Resolve-Path "$PSScriptRoot\*Help*\").Path -Recurse -File | Where-Object {
        $_.Extension -match '\.ps1|\.psm1|\.psd1|\.ps1xml' -and $_.Name -ne "Remove-Signature.ps1"
    }

    # Before we loop through and sign the Helper functions, we need to sign Remove-Signature.ps1
    $RemoveSignatureFilePath = $(Resolve-Path "$PSScriptRoot\*Help*\Remove-Signature.ps1").Path
    if (!$(Test-Path $RemoveSignatureFilePath)) {
        Write-Error "Unable to find the path $RemoveSignatureFilePath! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Because Set-Authenticode sometimes eats a trailing line when it is used, make sure Remove-Signature.ps1 doesn't break
    $SingatureLineRegex = '^# SIG # Begin signature block|^<!-- SIG # Begin signature block -->'
    $RemoveSignatureContent = Get-Content $RemoveSignatureFilePath
    [System.Collections.ArrayList]$UpdatedRemoveSignatureContent = @()
    foreach ($line in $RemoveSignatureContent) {
        if ($line -match $SingatureLineRegex) {
            $null = $UpdatedRemoveSignatureContent.Add("`n")
            break
        }
        else {
            $null = $UpdatedRemoveSignatureContent.Add($line)
        }
    }
    Set-Content -Path $RemoveSignatureFilePath -Value $UpdatedRemoveSignatureContent

    try {
        $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $RemoveSignatureFilePath -Cert $Cert
        if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -ne "Valid") {throw "There was a problem using the Set-AuthenticodeSignature cmdlet to sign the Remove-Signature.ps1 function! Halting!"}
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        return
    }

    # Dot Source the Remove-Signature function
    . $RemoveSignatureFilePath
    if (![bool]$(Get-Item Function:\Remove-Signature)) {
        Write-Error "Problem dot sourcing the Remove-Signature function! Halting!"
        $global:FunctionResult = "1"
        return
    }

    # Loop through the Help Scripts/Functions and sign them so that we can use them immediately if necessary
    Remove-Signature -FilePath $HelperFilestoSign.FullName

    [System.Collections.ArrayList]$FilesFailedToSign = @()
    foreach ($FilePath in $HelperFilestoSign.FullName) {
        try {
            $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $FilePath -cert $Cert
            if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -ne "Valid") {throw}
        }
        catch {
            $null = $FilesFailedToSign.Add($FilePath)
        }
    }

    if ($FilesFailedToSign.Count -gt 0) {
        Write-Error "Halting because we failed to digitally sign the following files:`n$($FilesFailedToSign -join "`n")"
        $global:FunctionResult = "1"
        return
    }
}

if (!$(Get-Module -ListAvailable PSDepend)) {
    & $(Resolve-Path "$PSScriptRoot\*Help*\Install-PSDepend.ps1").Path
}
try {
    Import-Module PSDepend
    $null = Invoke-PSDepend -Path "$PSScriptRoot\build.requirements.psd1" -Install -Import -Force

    # Hack to fix AppVeyor Error When attempting to Publish to PSGallery
    # The specific error this fixes is a problem with the Publish-Module cmdlet from PowerShellGet. PSDeploy
    # calls Publish-Module without the -Force parameter which results in this error: https://github.com/PowerShell/PowerShellGet/issues/79
    # This is more a problem with PowerShellGet than PSDeploy.
    <#
    Remove-Module PSDeploy
    $PSDeployScriptToEdit = Get-Childitem -Path $(Get-Module -ListAvailable PSDeploy).ModuleBase -File -Recurse -Filter "PSGalleryModule.ps1"
    [System.Collections.ArrayList][array]$PSDeployScriptContent = Get-Content $PSDeployScriptToEdit.FullName
    $LineOfInterest = $($PSDeployScriptContent | Select-String -Pattern ".*?Verbose[\s]+= \`$VerbosePreference").Matches.Value
    $IndexOfLineOfInterest = $PSDeployScriptContent.IndexOf($LineOfInterest)
    $PSDeployScriptContent.Insert($($IndexOfLineOfInterest+1),"            Force      = `$True")
    Set-Content -Path $PSDeployScriptToEdit.FullName -Value $PSDeployScriptContent
    #>
    Import-Module PSDeploy
}
catch {
    Write-Error $_
    $global:FunctionResult = "1"
    return
}

Set-BuildEnvironment -Force -Path $PSScriptRoot -ErrorAction SilentlyContinue

# Now the following Environment Variables with similar values should be available to use...
<#
    $env:BHBuildSystem = "Unknown"
    $env:BHProjectPath = "U:\powershell\ProjectRepos\Sudo"
    $env:BHBranchName = "master"
    $env:BHCommitMessage = "!deploy"
    $env:BHBuildNumber = 0
    $env:BHProjectName = "Sudo"
    $env:BHPSModuleManifest = "U:\powershell\ProjectRepos\Sudo\Sudo\Sudo.psd1"
    $env:BHModulePath = "U:\powershell\ProjectRepos\Sudo\Sudo"
    $env:BHBuildOutput = "U:\powershell\ProjectRepos\Sudo\BuildOutput"
#>

# Make sure everything is valid PowerShell before continuing...
$FilesToAnalyze = Get-ChildItem $PSScriptRoot -Recurse -File | Where-Object {
    $_.Extension -match '\.ps1|\.psm1|\.psd1'
}
[System.Collections.ArrayList]$InvalidPowerShell = @()
foreach ($FileItem in $FilesToAnalyze) {
    $contents = Get-Content -Path $FileItem.FullName -ErrorAction Stop
    $errors = $null
    $null = [System.Management.Automation.PSParser]::Tokenize($contents, [ref]$errors)
    if ($errors.Count -gt 0 -and $FileItem.Name -ne "$env:BHProjectName.psm1") {
        $null = $InvalidPowerShell.Add($FileItem)
    }
}
if ($InvalidPowerShell.Count -gt 0) {
    Write-Error "The following files are not valid PowerShell:`n$($InvalidPowerShell.FullName -join "`n")`nHalting!"
    $global:FunctionResult = "1"
    return
}

if ($Cert) {
    # NOTE: We don't want to include the Module's .psm1 or .psd1 yet because the psake.ps1 Compile Task hasn't finalized them yet...
    # NOTE: We don't want to sign build.ps1, Remove-Signature.ps1, or Helper functions because we just did that above...
    $HelperFilesToSignNameRegex = $HelperFilestoSign.Name | foreach {[regex]::Escape($_)}
    $RemoveSignatureFilePathRegex = [regex]::Escape($RemoveSignatureFilePath)
    [System.Collections.ArrayList][array]$FilesToSign = Get-ChildItem $env:BHProjectPath -Recurse -File | Where-Object {
        $_.Extension -match '\.ps1|\.psm1|\.psd1|\.ps1xml' -and
        $_.Name -notmatch "^$env:BHProjectName\.ps[d|m]1$" -and
        $_.Name -notmatch "^module\.requirements\.psd1" -and
        $_.Name -notmatch "^build\.requirements\.psd1" -and
        $_.Name -notmatch "^build\.ps1$" -and
        $_.Name -notmatch $($HelperFilesToSignNameRegex -join '|') -and
        $_.Name -notmatch $RemoveSignatureFilePathRegex
    }
    #$null = $FilesToSign.Add($(Get-Item $env:BHModulePath\Install-PSDepend.ps1))

    Remove-Signature -FilePath $FilesToSign.FullName

    [System.Collections.ArrayList]$FilesFailedToSign = @()
    foreach ($FilePath in $FilesToSign.FullName) {
        try {
            $SetAuthenticodeResult = Set-AuthenticodeSignature -FilePath $FilePath -cert $Cert
            if (!$SetAuthenticodeResult -or $SetAuthenticodeResult.Status -eq "HasMisMatch") {throw}
        }
        catch {
            $null = $FilesFailedToSign.Add($FilePath)
        }
    }

    if ($FilesFailedToSign.Count -gt 0) {
        Write-Error "Halting because we failed to digitally sign the following files:`n$($FilesFailedToSign -join "`n")"
        $global:FunctionResult = "1"
        return
    }
}

if (!$(Get-Module -ListAvailable PSDepend)) {
    & $(Resolve-Path "$PSScriptRoot\*Help*\Install-PSDepend.ps1").Path
}
try {
    Import-Module PSDepend
    $null = Invoke-PSDepend -Path "$PSScriptRoot\build.requirements.psd1" -Install -Import -Force

    # Hack to fix AppVeyor Error When attempting to Publish to PSGallery
    # The specific error this fixes is a problem with the Publish-Module cmdlet from PowerShellGet. PSDeploy
    # calls Publish-Module without the -Force parameter which results in this error: https://github.com/PowerShell/PowerShellGet/issues/79
    # This is more a problem with PowerShellGet than PSDeploy.
    Remove-Module PSDeploy -ErrorAction SilentlyContinue
    $PSDeployScriptToEdit = Get-Childitem -Path $(Get-Module -ListAvailable PSDeploy).ModuleBase -File -Recurse -Filter "PSGalleryModule.ps1"
    [System.Collections.ArrayList][array]$PSDeployScriptContent = Get-Content $PSDeployScriptToEdit.FullName
    $LineOfInterest = $($PSDeployScriptContent | Select-String -Pattern ".*?Verbose[\s]+= \`$VerbosePreference").Matches.Value
    $IndexOfLineOfInterest = $PSDeployScriptContent.IndexOf($LineOfInterest)
    $PSDeployScriptContent.Insert($($IndexOfLineOfInterest+1),"            Force      = `$True")
    Set-Content -Path $PSDeployScriptToEdit.FullName -Value $PSDeployScriptContent
    Import-Module PSDeploy
}
catch {
    Write-Error $_
    $global:FunctionResult = "1"
    return
}

if ([bool]$(Get-Module -Name $env:BHProjectName -ErrorAction SilentlyContinue)) {
    Remove-Module $env:BHProjectName -Force -ErrorAction SilentlyContinue
}

##### BEGIN Tasks Unique to this Module's Build #####

Remove-Module MiniLab -Force -ErrorAction SilentlyContinue

##### END Tasks Unique to this Module's Build #####

$psakeFile = "$env:BHProjectPath\psake.ps1"
if (!$(Test-Path $psakeFile)) {
    Write-Error "Unable to find the path $psakeFile! Halting!"
    $global:FunctionResult = "1"
    return
}

if ($PSBoundParameters.ContainsKey('help')) {
    Get-PSakeScriptTasks -buildFile $psakeFile | Format-Table -Property Name, Description, Alias, DependsOn
    return
}

##### END Prepare For Build #####

##### BEGIN PSAKE Build #####

# Add any test resources that you want to push to psake.ps1 and/or *.Tests.ps1 files
$TestResources = @{}

$InvokePSakeParams = @{}
if ($Cert) {
    $InvokePSakeParams.Add("Cert",$Cert)
}
if ($TestResources.Count -gt 0) {
    $InvokePSakeParams.Add("TestResources",$TestResources)
}

if ($InvokePSakeParams.Count -gt 0) {
    Invoke-Psake $psakeFile -taskList $Task -nologo -parameters $InvokePSakeParams -ErrorVariable IPSErr
}
else {
    Invoke-Psake $psakeFile -taskList $Task -nologo -ErrorAction Stop
}

exit ( [int]( -not $psake.build_success ) )

##### END PSAKE Build #####

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU3iuyNg2xJnPXn1JDOpkYws0H
# t3Sgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFfy0uxsIygxcpTF
# l6LD1ztT1Y7CMA0GCSqGSIb3DQEBAQUABIIBALepDjZVa65WvLnY2695unNrm8XJ
# wz41j+GPG57TD+eK3oNqIYKtt0dqXoTlBNiROV6R7Khlu33taVXbXY264G1HrZQ1
# fELSU1xUyKiXnYc+nQQ/Tf+KiRj5k6zJ0JPNgZu0oQ8Ur0jeuE4JQWwtihiTb7Wk
# TS3UpdN4S80rUVMB/vdNYAPX6twa5yS66LRgts+GdfEXd0mk6/MOxqRuGughspbS
# BQ07aI2JzMCg+++LAhSwDWMkiNh5Sk15QqB4bzXjieflKxqbfVz6bXROqDmgTXqx
# VWdxmsZIxg8dKj9KwyCyHk9q5Z7/fySh28NuKYufnbeU4+CagHOhz4nsIfA=
# SIG # End signature block
