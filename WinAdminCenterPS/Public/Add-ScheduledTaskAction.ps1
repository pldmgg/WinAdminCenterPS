<#
    
    .SYNOPSIS
        Adds a new action to existing scheduled task actions.
    
    .DESCRIPTION
        Adds a new action to existing scheduled task actions.

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
    
    .PARAMETER actionExecute
        The name of executable to run. By default looks in System32 if Working Directory is not provided
    
    .PARAMETER actionArguments
        The arguments for the executable.
    
    .PARAMETER workingDirectory
        The path to working directory
    
#>
function Add-ScheduledTaskAction {
    param (
        [parameter(Mandatory=$true)]
        [string]
        $taskName,
        [parameter(Mandatory=$true)]
        [string]
        $taskPath,
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
    
    ######################################################
    #### Main script
    ######################################################
    
    # Create action object
    $action = New-ScheduledTaskAction @taskActionParams
    
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $actionsArray =  $task.Actions
    $actionsArray += $action 
    Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $actionsArray
}