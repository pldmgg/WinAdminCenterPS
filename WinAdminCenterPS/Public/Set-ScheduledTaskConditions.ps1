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
    
    .PARAMETER dontStopOnIdleEnd
        Indicates that Task Scheduler does not terminate the task if the idle condition ends before the task is completed.
        
    .PARAMETER idleDurationInMins
        Specifies the amount of time that the computer must be in an idle state before Task Scheduler runs the task.
        
    .PARAMETER idleWaitTimeoutInMins
       Specifies the amount of time that Task Scheduler waits for an idle condition to occur before timing out.
        
    .PARAMETER restartOnIdle
       Indicates that Task Scheduler restarts the task when the computer cycles into an idle condition more than once.
        
    .PARAMETER runOnlyIfIdle
        Indicates that Task Scheduler runs the task only when the computer is idle.
        
    .PARAMETER allowStartIfOnBatteries
        Indicates that Task Scheduler starts if the computer is running on battery power.
        
    .PARAMETER dontStopIfGoingOnBatteries
        Indicates that the task does not stop if the computer switches to battery power.
    
    .PARAMETER runOnlyIfNetworkAvailable
        Indicates that Task Scheduler runs the task only when a network is available. Task Scheduler uses the NetworkID parameter and NetworkName parameter that you specify in this cmdlet to determine if the network is available.
    
    .PARAMETER networkId
        Specifies the ID of a network profile that Task Scheduler uses to determine if the task can run. You must specify the ID of a network if you specify the RunOnlyIfNetworkAvailable parameter.
    
    .PARAMETER networkName
       Specifies the name of a network profile that Task Scheduler uses to determine if the task can run. The Task Scheduler UI uses this setting for display purposes. Specify a network name if you specify the RunOnlyIfNetworkAvailable parameter.
    
#>
function Set-ScheduledTaskConditions {
    param (
        [parameter(Mandatory=$true)]
        [string]
        $taskName,
        [parameter(Mandatory=$true)]
        [string]
        $taskPath,
        [Boolean]
        $stopOnIdleEnd,
        [string]
        $idleDuration,
        [string]
        $idleWaitTimeout,
        [Boolean]
        $restartOnIdle,
        [Boolean]
        $runOnlyIfIdle,
        [Boolean]
        $disallowStartIfOnBatteries,
        [Boolean]
        $stopIfGoingOnBatteries,
        [Boolean]
        $wakeToRun
    )
    
    Import-Module ScheduledTasks
    
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath;
    
    # Idle related conditions.
    $task.settings.RunOnlyIfIdle = $runOnlyIfIdle;
    
    $task.Settings.IdleSettings.IdleDuration = $idleDuration;
    $task.Settings.IdleSettings.WaitTimeout = $idleWaitTimeout;
    
    $task.Settings.IdleSettings.RestartOnIdle = $restartOnIdle;
    $task.Settings.IdleSettings.StopOnIdleEnd = $stopOnIdleEnd;
    
    # Power related condition.
    $task.Settings.DisallowStartIfOnBatteries = $disallowStartIfOnBatteries;
    
    $task.Settings.StopIfGoingOnBatteries = $stopIfGoingOnBatteries;
    
    $task.Settings.WakeToRun = $wakeToRun;
    
    $task | Set-ScheduledTask;
}