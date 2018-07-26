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
   
    .PARAMETER taskPath
        The task path.
   
    .PARAMETER triggerClassName
        The cim class Name for Trigger being edited.
   
    .PARAMETER triggersToCreate
        Collections of triggers to create/edit, should be of same type. The script will preserve any other trigger than cim class specified in triggerClassName. 
        This is done because individual triggers can not be identified by Id. Everytime update to any trigger is made we recreate all triggers that are of the same type supplied by user in triggers to create collection.

#>
function Update-ScheduledTaskTrigger {
    param (
       [parameter(Mandatory=$true)]
       [string]
       $taskName,
       [parameter(Mandatory=$true)]
       [string]
       $taskPath,
       [string]
       $triggerClassName,
       [object[]]
       $triggersToCreate
   )
   
   Import-Module ScheduledTasks
   
   ######################################################
   #### Functions
   ######################################################
   
   
   function Create-Trigger 
    {
       Param (
       [object]
       $trigger
       )
   
       if($trigger) 
       {
           #
           # Prepare task trigger parameter bag
           #
           $taskTriggerParams = @{} 
           # Parameter is not required while creating Logon trigger /startup Trigger
           if ($trigger.triggerAt -and $trigger.triggerFrequency -in ('Daily','Weekly', 'Once')) {
              $taskTriggerParams.At =  $trigger.triggerAt;
           }
      
       
           # Build optional switches
           if ($trigger.triggerFrequency -eq 'Daily')
           {
               $taskTriggerParams.Daily = $true;
           }
           elseif ($trigger.triggerFrequency -eq 'Weekly')
           {
               $taskTriggerParams.Weekly = $true;
               if ($trigger.weeksInterval -and $trigger.weeksInterval -ne 0) 
               {
                  $taskTriggerParams.WeeksInterval = $trigger.weeksInterval;
               }
               if ($trigger.daysOfWeek) 
               {
                  $taskTriggerParams.DaysOfWeek = $trigger.daysOfWeek;
               }
           }
           elseif ($trigger.triggerFrequency -eq 'Once')
           {
               $taskTriggerParams.Once = $true;
           }
           elseif ($trigger.triggerFrequency -eq 'AtLogOn')
           {
               $taskTriggerParams.AtLogOn = $true;
           }
           elseif ($trigger.triggerFrequency -eq 'AtStartup')
           {
               $taskTriggerParams.AtStartup = $true;
           }
   
   
           if ($trigger.daysInterval -and $trigger.daysInterval -ne 0) 
           {
              $taskTriggerParams.DaysInterval = $trigger.daysInterval;
           }
           
           if ($trigger.username) 
           {
              $taskTriggerParams.User = $trigger.username;
           }
   
   
           # Create trigger object
           $triggerNew = New-ScheduledTaskTrigger @taskTriggerParams
   
           $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
          
           Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggerNew | out-null
   
           $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
        
   
           if ($trigger.repetitionInterval -and $task.Triggers[0].Repetition -ne $null) 
           {
              $task.Triggers[0].Repetition.Interval = $trigger.repetitionInterval;
           }
           if ($trigger.repetitionDuration -and $task.Triggers[0].Repetition -ne $null) 
           {
              $task.Triggers[0].Repetition.Duration = $trigger.repetitionDuration;
           }
           if ($trigger.stopAtDurationEnd -and $task.Triggers[0].Repetition -ne $null) 
           {
              $task.Triggers[0].Repetition.StopAtDurationEnd = $trigger.stopAtDurationEnd;
           }
           if($trigger.executionTimeLimit) 
           {
               $task.Triggers[0].ExecutionTimeLimit = $trigger.executionTimeLimit;
           }
           if($trigger.randomDelay -ne '')
           {
               if([bool]($task.Triggers[0].PSobject.Properties.name -eq "RandomDelay")) 
               {
                   $task.Triggers[0].RandomDelay = $trigger.randomDelay;
               }
   
               if([bool]($task.Triggers[0].PSobject.Properties.name -eq "Delay")) 
               {
                   $task.Triggers[0].Delay = $trigger.randomDelay;
               }
           }
   
           if($trigger.enabled -ne $null) 
           {
               $task.Triggers[0].Enabled = $trigger.enabled;
           }
   
           if($trigger.endBoundary -and $trigger.endBoundary -ne '') 
           {
               $date = [datetime]($trigger.endBoundary);
               $task.Triggers[0].EndBoundary = $date.ToString("yyyy-MM-ddTHH:mm:sszzz"); #convert date to specific string.
           }
   
           # Activation date is also stored in StartBoundary for Logon/Startup triggers. Setting it in appropriate context
           if($trigger.triggerAt -ne '' -and $trigger.triggerAt -ne $null -and $trigger.triggerFrequency -in ('AtLogOn','AtStartup')) 
           {
               $date = [datetime]($trigger.triggerAt);
               $task.Triggers[0].StartBoundary = $date.ToString("yyyy-MM-ddTHH:mm:sszzz"); #convert date to specific string.
           }
   
   
           return  $task.Triggers[0];
          } # end if
    }
   
   ######################################################
   #### Main script
   ######################################################
   
   $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
   $triggers = $task.Triggers;
   $allTriggers = @()
   try {
   
       foreach ($t in $triggers)
       {
           # Preserve all the existing triggers which are of different type then the modified trigger type.
           if ($t.CimClass.CimClassName -ne $triggerClassName) 
           {
               $allTriggers += $t;
           } 
       }
   
        # Once all other triggers are preserved, recreate the ones passed on by the UI
        foreach ($t in $triggersToCreate)
        {
           $newTrigger = Create-Trigger -trigger $t
           $allTriggers += $newTrigger;
        }
   
       Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $allTriggers
   } 
   catch 
   {
        Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggers
        throw $_.Exception
   }
   
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU92D4CVZlNwsLFBXPrONkLEEs
# 7Eigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBNVfLM9845fwxEu
# sBfytpyuGqmzMA0GCSqGSIb3DQEBAQUABIIBAEDQmk0ukQg8Wj/tuj28Oaau6KAP
# jZn1v5Djsk3OfilNCwBZb6TURhGzvzmNE40uppLKtyRHetG1RRib2aHzdBLNva01
# o/Dr+lCMJ3LClrTCjZkihINuKMnKRLIssE3HvWjr4pgRiR3zH5Ch0m4VolYvX07V
# IgZKKhyo/e+Auzjz50ensWtO+fT7/PmGp68D11MioP6HyYljo0RbymuSEktotAEI
# l6JzEkFRLunC9psLI+zwrLsMrqornTpTQ7wZ1VdDjT53zds8VjwE3i5z3apKjc0j
# VgGz9ZGrz2V3vGwwP1MoOJBouz/AuF/VW1F9cuGutriO1aHM3zg+hfZXGI4=
# SIG # End signature block
