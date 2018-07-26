<#
   
    .SYNOPSIS
        Adds a new trigger to existing scheduled task triggers.
   
    .DESCRIPTION
        Adds a new trigger to existing scheduled task triggers.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
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