<#
    
    .SYNOPSIS
        Script that exports certificate.
    
    .DESCRIPTION
        Script that exports certificate.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Export-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $certPath,
        [Parameter(Mandatory = $true)]
        [String]
        $exportType,
        [String]
        $fileName,
        [string]
        $exportChain,
        [string]
        $exportProperties,
        [string]
        $usersAndGroups,
        [string]
        $password,
        [string]
        $invokeUserName,
        [string]
        $invokePassword
    )
    
    # Notes: invokeUserName and invokePassword are not used on this version. Remained for future use.
    
    $Script = @'
try {
    Import-Module PKI
    if ($exportChain -eq "CertificateChain")
    {
        $chainOption = "BuildChain";
    }
    else
    {
        $chainOption = "EndEntityCertOnly";
    }

    $ExportPfxCertParams = @{ Cert = $certPath; FilePath = $tempPath; ChainOption = $chainOption }
    if ($exportProperties -ne "Extended")
    {
        $ExportPfxCertParams.NoProperties = $true
    }

    if ($password)
    {
        Add-Type -AssemblyName System.Security
        $encode = new-object System.Text.UTF8Encoding
        $encrypted = [System.Convert]::FromBase64String($password)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $password = $encode.GetString($decrypted)
        $pwd = ConvertTo-SecureString -String $password -Force -AsPlainText;
        $ExportPfxCertParams.Password = $pwd
    }

    if ($usersAndGroups)
    {
        $ExportPfxCertParams.ProtectTo = $usersAndGroups
    }

    Export-PfxCertificate @ExportPfxCertParams | ConvertTo-Json -depth 10 | Out-File $ResultFile
} catch {
    $_.Exception.Message | ConvertTo-Json | Out-File $ErrorFile
}
'@
    
    function CalculateFilePath
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $exportType,
            [Parameter(Mandatory = $true)]
            [String]
            $certPath
        )
    
        $extension = $exportType.ToLower();
        if ($exportType.ToLower() -eq "cert")
        {
            $extension = "cer";
        }
    
        if (!$fileName)
        {
            $arr = $certPath.Split('\\');
            $fileName = $arr[3];
        }
    
        (Get-Childitem -Path Env:* | where-Object {$_.Name -eq "TEMP"}).value  + "\" + $fileName + "." + $extension
    }
    
    $tempPath = CalculateFilePath -exportType $exportType -certPath $certPath;
    if ($exportType -ne "Pfx")
    {
        Export-Certificate -Cert $certPath -FilePath $tempPath -Type $exportType -Force
        return;
    }
    
    # PFX private key handlings
    if ($password) {
        # encrypt password with current user.
        Add-Type -AssemblyName System.Security
        $encode = new-object System.Text.UTF8Encoding
        $bytes = $encode.GetBytes($password)
        $encrypt = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $password = [System.Convert]::ToBase64String($encrypt)
    }
    
    # Pass parameters to script and generate script file in temp folder
    $ResultFile = $env:temp + "\export-certificate_result.json"
    $ErrorFile = $env:temp + "\export-certificate_error.json"
    if (Test-Path $ErrorFile) {
        Remove-Item $ErrorFile
    }
    
    if (Test-Path $ResultFile) {
        Remove-Item $ResultFile
    }
    
    $Script = '$certPath=' + "'$certPath';" +
              '$tempPath=' + "'$tempPath';" +
              '$exportType=' + "'$exportType';" +
              '$exportChain=' + "'$exportChain';" +
              '$exportProperties=' + "'$exportProperties';" +
              '$usersAndGroups=' + "'$usersAndGroups';" +
              '$password=' + "'$password';" +
              '$ResultFile=' + "'$ResultFile';" +
              '$ErrorFile=' + "'$ErrorFile';" +
              $Script
    $ScriptFile = $env:temp + "\export-certificate.ps1"
    $Script | Out-File $ScriptFile
    
    # Create a scheduled task
    $TaskName = "SMEExportCertificate"
    
    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile"
    if (!$Role)
    {
        Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
    }
    
    $Scheduler = New-Object -ComObject Schedule.Service
    
    #Try to connect to schedule service 3 time since it may fail the first time
    for ($i=1; $i -le 3; $i++)
    {
        Try
        {
            $Scheduler.Connect()
            Break
        }
        Catch
        {
            if ($i -ge 3)
            {
                Write-EventLog -LogName Application -Source "SME Export certificate" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
                Write-Error "Can't connect to Schedule service" -ErrorAction Stop
            }
            else
            {
                Start-Sleep -s 1
            }
        }
    }
    
    $RootFolder = $Scheduler.GetFolder("\")
    #Delete existing task
    if ($RootFolder.GetTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Write-Debug("Deleting existing task" + $TaskName)
        $RootFolder.DeleteTask($TaskName,0)
    }
    
    $Task = $Scheduler.NewTask(0)
    $RegistrationInfo = $Task.RegistrationInfo
    $RegistrationInfo.Description = $TaskName
    $RegistrationInfo.Author = $User.Name
    
    $Triggers = $Task.Triggers
    $Trigger = $Triggers.Create(7) #TASK_TRIGGER_REGISTRATION: Starts the task when the task is registered.
    $Trigger.Enabled = $true
    
    $Settings = $Task.Settings
    $Settings.Enabled = $True
    $Settings.StartWhenAvailable = $True
    $Settings.Hidden = $False
    
    $Action = $Task.Actions.Create(0)
    $Action.Path = "powershell"
    $Action.Arguments = $arg
    
    #Tasks will be run with the highest privileges
    $Task.Principal.RunLevel = 1
    
    #### example Start the task with user specified invoke username and password
    ####$Task.Principal.LogonType = 1
    ####$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, $invokeUserName, $invokePassword, 1) | Out-Null
    
    #### Start the task with SYSTEM creds
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
    #Wait for running task finished
    $RootFolder.GetTask($TaskName).Run(0) | Out-Null
    while ($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Start-Sleep -s 2
    }
    
    #Clean up
    $RootFolder.DeleteTask($TaskName,0)
    Remove-Item $ScriptFile
    #Return result
    if (Test-Path $ErrorFile) {
        $result = Get-Content -Raw -Path $ErrorFile | ConvertFrom-Json
        Remove-Item $ErrorFile
        Remove-Item $ResultFile
        throw $result
    }
    
    if (Test-Path $ResultFile)
    {
        $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
        Remove-Item $ResultFile
        return $result
    }
    
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUWJaiCb1hX5Mym7Vg0vKxkAKs
# sRagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFGvCB3q2EjdiWe43
# fpQSuhwo03xhMA0GCSqGSIb3DQEBAQUABIIBALgQAvHwAPvHAJad9zkm0zepCMFN
# RjcwynqwYjMcKy9qeV6HtkUvKujpvxHONTBvSMOS8VIpM0IpOEuyqSVVXuOqW0GI
# bMDWI7HpHI7BP17Rfg5vHmGV20KrlwloI778f0YWuhE0UUp5VU/ihBjUUDJLTwEs
# zTm8BoHzceqsI0oSTwq3+XYPMAO++4lmcI8hkg5EvtGXtbYaFfdyXQZwvypWdrZS
# zSCB9KiaB0vYNpDoVBqKjn8j8FI7dm1F7mMYfF6VaXRU/d7TETYyP1vwbDWG83H0
# ek5+P6f5yPqlEfpdWL6uUCsoAFIMm03Tt6KaWXRmQfeFisFvqb9vgKsWnkA=
# SIG # End signature block
