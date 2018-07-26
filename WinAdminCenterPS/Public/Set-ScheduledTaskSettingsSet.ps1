<#
    
    .SYNOPSIS
        Set/modify scheduled task setting set.
    
    .DESCRIPTION
        Set/modify scheduled task setting set.

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
    
    .PARAMETER disallowDemandStart
        Indicates that the task cannot be started by using either the Run command or the Context menu.
    
    .PARAMETER startWhenAvailable
        Indicates that Task Scheduler can start the task at any time after its scheduled time has passed.
    
    .PARAMETER executionTimeLimitInMins
        Specifies the amount of time that Task Scheduler is allowed to complete the task.
    
    .PARAMETER restartIntervalInMins
        Specifies the amount of time between Task Scheduler attempts to restart the task.
    
    .PARAMETER restartCount
        Specifies the number of times that Task Scheduler attempts to restart the task.
    
    .PARAMETER deleteExpiredTaskAfterInMins
        Specifies the amount of time that Task Scheduler waits before deleting the task after it expires.
    
    .PARAMETER multipleInstances
        Specifies the policy that defines how Task Scheduler handles multiple instances of the task. Possible Enum values Parallel, Queue, IgnoreNew
    
    .PARAMETER disallowHardTerminate
        Indicates that the task cannot be terminated by using TerminateProcess.
    
#>
function Set-ScheduledTaskSettingsSet {
    param (
        [parameter(Mandatory=$true)]
        [string]
        $taskName,
        [parameter(Mandatory=$true)]
        [string]
        $taskPath,
        [Boolean]
        $allowDemandStart,
        [Boolean]
        $allowHardTerminate,
        [Boolean]
        $startWhenAvailable, 
        [string]
        $executionTimeLimit, 
        [string]
        $restartInterval, 
        [Int32]
        $restartCount, 
        [string]
        $deleteExpiredTaskAfter,
        [Int32]
        $multipleInstances  #Parallel, Queue, IgnoreNew
        
    )
    
    Import-Module ScheduledTasks
    
    #
    # Prepare action parameter bag
    #
    
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath;
    
    $task.settings.AllowDemandStart =  $allowDemandStart;
    $task.settings.AllowHardTerminate = $allowHardTerminate;
    
    $task.settings.StartWhenAvailable = $startWhenAvailable;
    
    if ($executionTimeLimit -eq $null -or $executionTimeLimit -eq '') {
        $task.settings.ExecutionTimeLimit = 'PT0S';
    } 
    else 
    {
        $task.settings.ExecutionTimeLimit = $executionTimeLimit;
    } 
    
    if ($restartInterval -eq $null -or $restartInterval -eq '') {
        $task.settings.RestartInterval = $null;
    } 
    else
    {
        $task.settings.RestartInterval = $restartInterval;
    } 
    
    if ($restartCount -gt 0) {
        $task.settings.RestartCount = $restartCount;
    }
    <#if ($deleteExpiredTaskAfter -eq '' -or $deleteExpiredTaskAfter -eq $null) {
        $task.settings.DeleteExpiredTaskAfter = $null;
    }
    else 
    {
        $task.settings.DeleteExpiredTaskAfter = $deleteExpiredTaskAfter;
    }#>
    
    if ($multipleInstances) {
        $task.settings.MultipleInstances = $multipleInstances;
    }
    
    $task | Set-ScheduledTask ;
}