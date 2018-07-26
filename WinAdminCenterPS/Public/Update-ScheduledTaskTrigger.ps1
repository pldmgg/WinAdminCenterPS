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