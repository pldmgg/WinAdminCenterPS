<#
   
    .SYNOPSIS
        Adds a new trigger to existing scheduled task triggers.
   
    .DESCRIPTION
        Adds a new trigger to existing scheduled task triggers.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
   
    .ROLE
        Administrators
   
    .PARAMETER taskName
        The name of the task
   
    .PARAMETER taskDescription
        The description of the task.
   
    .PARAMETER taskPath
        The task path.
   
   .PARAMETER triggerAt
        The date/time to trigger the task.    
   
    .PARAMETER triggerFrequency
        The frequency of the task occurence. Possible values Daily, Weekly, Monthly, Once, AtLogOn, AtStartup
   
    .PARAMETER daysInterval
        The number of days interval to run task.
   
    .PARAMETER weeklyInterval
        The number of weeks interval to run task.
   
    .PARAMETER daysOfWeek
        The days of the week to run the task. Possible values can be an array of Sunday, Monday, Tuesday, Wednesday, Thursday, Friday, Saturday
   
    .PARAMETER username
        The username associated with the trigger.
   
    .PARAMETER repetitionInterval
        The repitition interval.
   
    .PARAMETER repetitionDuration
        The repitition duration.
   
    .PARAMETER randomDelay
        The delay before running the trigger.
    
#>
function Add-ScheduledTaskTrigger {
    param (
       [parameter(Mandatory=$true)]
       [string]
       $taskName,
       [parameter(Mandatory=$true)]
       [string]
       $taskPath,
       [AllowNull()][System.Nullable[DateTime]]
       $triggerAt,
       [parameter(Mandatory=$true)]
       [string]
       $triggerFrequency, 
       [Int32]
       $daysInterval, 
       [Int32]
       $weeksInterval,
       [string[]]
       $daysOfWeek,
       [string]
       $username,
       [string]
       $repetitionInterval,
       [string]
       $repetitionDuration,
       [boolean]
       $stopAtDurationEnd,
       [string]
       $randomDelay,
       [string]
       $executionTimeLimit
   )
   
   Import-Module ScheduledTasks
   
   #
   # Prepare task trigger parameter bag
   #
   $taskTriggerParams = @{} 
   
   if ($triggerAt) {
      $taskTriggerParams.At =  $triggerAt;
   }
      
       
   # Build optional switches
   if ($triggerFrequency -eq 'Daily')
   {
       $taskTriggerParams.Daily = $true;
       if ($daysInterval -ne 0) 
       {
          $taskTriggerParams.DaysInterval = $daysInterval;
       }
   }
   elseif ($triggerFrequency -eq 'Weekly')
   {
       $taskTriggerParams.Weekly = $true;
       if ($weeksInterval -ne 0) 
       {
           $taskTriggerParams.WeeksInterval = $weeksInterval;
       }
       if ($daysOfWeek -and $daysOfWeek.Length -gt 0) 
       {
           $taskTriggerParams.DaysOfWeek = $daysOfWeek;
       }
   }
   elseif ($triggerFrequency -eq 'Once')
   {
       $taskTriggerParams.Once = $true;
   }
   elseif ($triggerFrequency -eq 'AtLogOn')
   {
       $taskTriggerParams.AtLogOn = $true;
   }
   elseif ($triggerFrequency -eq 'AtStartup')
   {
       $taskTriggerParams.AtStartup = $true;
   }
   
   if ($username) 
   {
      $taskTriggerParams.User = $username;
   }
   
   
   ######################################################
   #### Main script
   ######################################################
   
   # Create trigger object
   $triggersArray = @()
   $triggerNew = New-ScheduledTaskTrigger @taskTriggerParams
   
   $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
   $triggersArray =  $task.Triggers
   
   Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggerNew | out-null
   
   $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
   $trigger = $task.Triggers[0]
   
   
   if ($repetitionInterval -and $trigger.Repetition -ne $null) 
   {
      $trigger.Repetition.Interval = $repetitionInterval;
   }
   if ($repetitionDuration -and $trigger.Repetition -ne $null) 
   {
      $trigger.Repetition.Duration = $repetitionDuration;
   }
   if ($stopAtDurationEnd -and $trigger.Repetition -ne $null) 
   {
      $trigger.Repetition.StopAtDurationEnd = $stopAtDurationEnd;
   }
   if($executionTimeLimit) {
    $task.Triggers[0].ExecutionTimeLimit = $executionTimeLimit;
   }
   
   if([bool]($task.Triggers[0].PSobject.Properties.name -eq "RandomDelay")) 
   {
       $task.Triggers[0].RandomDelay = $randomDelay;
   }
   
   if([bool]($task.Triggers[0].PSobject.Properties.name -eq "Delay")) 
   {
       $task.Triggers[0].Delay = $randomDelay;
   }
   
   $triggersArray += $trigger
   
   Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggersArray 
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUQt/8S2IlY9NsFz7U7gSRb1bo
# rQSgggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFCNreyWxx1gajtVk
# 5Vipaq+su9P5MA0GCSqGSIb3DQEBAQUABIIBAIn7pPzHcyla7VPQCsgKTbfjrKSg
# Bmj3uZ3AlEW3UN8zNo8IRFhIOxDgzsm5I4Wo+eVPxSPNd6PNqqm2DaDEevdY/g1n
# 1lwnrkVv/J0vIpJCwjruyfMe4OE8Hiq/5jQ41IuZ9q0q6CWwNU+2kz45UtY/40P/
# syjs7M2j96EC/QD2mnks/jentIbrSBBbR0E+wqXtyFquKFq86+7lQGhId6WJFPVE
# Mcn4MZi3TXfxLgy3bWV97y1anidyJMtiL6aGwLl7rCsnlWmYbgQvQauNutXnC58D
# GGchiyLgse7nDlcesUiVMsdVlGS5MY7OdvHbOwp2+MbJuOy87aGvx7j+QNs=
# SIG # End signature block
