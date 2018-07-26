<#

    .SYNOPSIS
        Update device driver.

    .DESCRIPTION
        Update device driver.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function Update-DeviceDriver {
    param(
        $Updates 
    )

    $Script = @'
$NumberOfUpdate = 1;
$updateCount = $Updates.Count;
Foreach($Update in $Updates)
{
    Write-Progress -Activity 'Downloading updates' -Status `"[$NumberOfUpdate/$updateCount]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate/$updateCount * 100));
    $NumberOfUpdate++;
    Write-Debug `"Show` update` to` download:` $($Update.Title)`" ;
    $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl';
    $UpdatesToDownload.Add($Update) | Out-Null;

    $UpdateSession = New-Object -ComObject 'Microsoft.Update.Session';
    $Downloader = $UpdateSession.CreateUpdateDownloader();
    $Downloader.Updates = $UpdatesToDownload;
    Try
    {
        Write-Debug 'Try download update';
        $DownloadResult = $Downloader.Download();
    } <#End Try#>
    Catch
    {
        If($_ -match 'HRESULT: 0x80240044')
        {
            Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
        } <#End If $_ -match 'HRESULT: 0x80240044'#>

        Return
    } <#End Catch#>

    Write-Debug 'Check ResultCode';
    Switch -exact ($DownloadResult.ResultCode)
    {
        0   { $Status = 'NotStarted'; }
        1   { $Status = 'InProgress'; }
        2   { $Status = 'Downloaded'; }
        3   { $Status = 'DownloadedWithErrors'; }
        4   { $Status = 'Failed'; }
        5   { $Status = 'Aborted'; }
    } <#End Switch#>

    If($DownloadResult.ResultCode -eq 2)
    {
        Write-Debug 'Downloaded then send update to next stage';
        $objCollectionDownload.Add($Update) | Out-Null;
    } <#End If $DownloadResult.ResultCode -eq 2#>

}

$ReadyUpdatesToInstall = $objCollectionDownload.count;
Write-Verbose `"Downloaded` [$ReadyUpdatesToInstall]` Updates` to` Install`" ;
If($ReadyUpdatesToInstall -eq 0)
{
    Return;
} <#End If $ReadyUpdatesToInstall -eq 0#>

$NeedsReboot = $false;
$NumberOfUpdate = 1;
<#install updates#>
Foreach($Update in $objCollectionDownload)
{
    Write-Progress -Activity 'Installing updates' -Status `"[$NumberOfUpdate/$ReadyUpdatesToInstall]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate/$ReadyUpdatesToInstall * 100));
    Write-Debug 'Show update to install: $($Update.Title)';

    Write-Debug 'Send update to install collection';
    $objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
    $objCollectionTmp.Add($Update) | Out-Null;

    $objInstaller = $objSession.CreateUpdateInstaller();
    $objInstaller.Updates = $objCollectionTmp;

    Try
    {
        Write-Debug 'Try install update';
        $InstallResult = $objInstaller.Install();
    } <#End Try#>
    Catch
    {
        If($_ -match 'HRESULT: 0x80240044')
        {
            Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
        } <#End If $_ -match 'HRESULT: 0x80240044'#>

        Return;
    } #End Catch

    If(!$NeedsReboot)
    {
        Write-Debug 'Set instalation status RebootRequired';
        $NeedsReboot = $installResult.RebootRequired;
    } <#End If !$NeedsReboot#>
    $NumberOfUpdate++;
} <#End Foreach $Update in $objCollectionDownload#>
'@

    #Pass parameters to script and generate script file in localappdata folder
    $ScriptFile = $env:LocalAppData + "\Install-Drivers.ps1"
    $Script = '$updates =' + $Updates + $Script
    $Script | Out-File $ScriptFile
    if (-Not(Test-Path $ScriptFile)) {
        $message = "Failed to create file:" + $ScriptFile
        Write-Error $message
        return #If failed to create script file, no need continue just return here
    }

    #Create a scheduled task
    $TaskName = "SMEWindowsUpdateInstallDrivers"

    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile"
    if(!$Role)
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
            if($i -ge 3)
            {
                Write-EventLog -LogName Application -Source "SME Windows Updates Install Updates" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
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
    if($RootFolder.GetTasks(0) | Where-Object {$_.Name -eq $TaskName})
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

    #Start the task to run in Local System account. 6: TASK_CREATE_OR_UPDATE
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
    #Wait for running task finished
    $RootFolder.GetTask($TaskName).Run(0) | Out-Null
    while($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Start-Sleep -s 1
    }

    #Clean up
    $RootFolder.DeleteTask($TaskName,0)
    Remove-Item $ScriptFile
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUAnFvvkwDBHEUe57Lxv/+RRCV
# nc+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFPqc2iVZLWLQzUCL
# p753uQpTLtO9MA0GCSqGSIb3DQEBAQUABIIBAEPrhnVJ9UN4MK0NbXyyt2Guizb2
# kI8pwYkXtBDQq9LGt7KACCZgL8Ggs2h+Uu2uIDYgHp66s2RFaXa6SxqioX3V9tP7
# T8PDK2gNOx+AnPoCTboVFqdNcKx53EOKqnwrLKRGgom3PJak/sX5skH43MIGsZfD
# u4y+HOubdston5msq5SHJbf0aHd5fL8e/VGuzZfTRzJBN2YZCY1u7ChSrWH6D06g
# qOj722LuclV95frwDGQCSvKQ6allPVZ72FcOOj0aVFaoaPApU6EmFRpTymOK0FZp
# s2114LWVrX1YO40qacjtIwuBmowpwUC/avpx/WAsTb0i3pWe5mQqS+YsQYc=
# SIG # End signature block
