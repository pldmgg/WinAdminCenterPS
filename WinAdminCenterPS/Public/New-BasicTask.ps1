function New-BasicTask {
    <#
    
    .SYNOPSIS
        Creates and registers a new scheduled task.
    
    .DESCRIPTION
        Creates and registers a new scheduled task.

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
    
    .PARAMETER actionExecute
        The name of executable to run. By default looks in System32 if Working Directory is not provided
    
    .PARAMETER actionArguments
        The arguments for the executable.
    
    .PARAMETER workingDirectory
        The path to working directory
    #>
    
    param (
        [parameter(Mandatory=$true)]
        [string]
        $taskName,
        [string]
        $taskDescription,
        [parameter(Mandatory=$true)]
        [string]
        $taskPath,
        [parameter(Mandatory=$true)]
        [string]
        $triggerFrequency,
        [AllowNull()][System.Nullable[DateTime]]
        $triggerAt,
        [Int32]
        $daysInterval,
        [Int32]
        $weeklyInterval,
        [string[]]
        $daysOfWeek,
        [parameter(Mandatory=$true)]
        [string]
        $actionExecute,
        [string]
        $actionArguments,
        [string]
        $workingDirectory
    )
    
    Import-Module ScheduledTasks
    
    #
    # Prepare action parameter bag
    #
    $taskActionParams = @{
        Execute = $actionExecute;
    }
    
    if ($actionArguments) {
        $taskActionParams.Argument = $actionArguments;
    }
    if ($workingDirectory) {
         $taskActionParams.WorkingDirectory = $workingDirectory;
    }
    # Create action object
    $action = New-ScheduledTaskAction @taskActionParams
    
    #
    # Prepare task trigger parameter bag
    #
    $taskTriggerParams = @{}
    
    # Build optional switches
    
    if ($triggerAt) {
      $taskTriggerParams.At =  $triggerAt;
    }
    
    if ($triggerFrequency -eq 'Daily')
    {
        $taskTriggerParams.Daily = $true;
    }
    elseif ($triggerFrequency -eq 'Weekly')
    {
        $taskTriggerParams.Weekly = $true;
    }
    elseif ($triggerFrequency -eq 'Monthly')
    {
        $taskTriggerParams.Monthly = $true;
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
    
    
    if ($daysInterval)
    {
       $taskTriggerParams.DaysInterval = $daysInterval;
    }
    if ($weeklyInterval)
    {
       $taskTriggerParams.WeeksInterval = $weeklyInterval;
    }
    if ($daysOfWeek)
    {
       $taskTriggerParams.DaysOfWeek = $daysOfWeek;
    }
    
    # Create trigger object
    $trigger = New-ScheduledTaskTrigger @taskTriggerParams
    
    # Default settings
    $settingSet = New-ScheduledTaskSettingsSet
    
    ######################################################
    #### Main script
    ######################################################
    Register-ScheduledTask -TaskName  $taskName -TaskPath $taskPath -Trigger $trigger -Action $action -Description $taskDescription -Settings $settingSet
    
}