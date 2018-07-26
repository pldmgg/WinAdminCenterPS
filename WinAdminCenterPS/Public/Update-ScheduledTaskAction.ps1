<#
    
    .SYNOPSIS
        Updates existing scheduled task action.
    
    .DESCRIPTION
        Updates existing scheduled task action.

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
    
    .PARAMETER oldActionExecute
        The name of executable to run. By default looks in System32 if Working Directory is not provided
    
    .PARAMETER newActionExecute
        The name of executable to run. By default looks in System32 if Working Directory is not provided
    
    .PARAMETER oldActionArguments
        The arguments for the executable.
    
    .PARAMETER newActionArguments
        The arguments for the executable.
    
    .PARAMETER oldWorkingDirectory
        The path to working directory
    
    .PARAMETER newWorkingDirectory
        The path to working directory
    
#>
function Update-ScheduledTaskAction {
    param (
        [parameter(Mandatory=$true)]
        [string]
        $taskName,
        [parameter(Mandatory=$true)]
        [string]
        $taskPath,
        [parameter(Mandatory=$true)]
        [string]
        $newActionExecute,
        [parameter(Mandatory=$true)]
        [string]
        $oldActionExecute,
        [string]
        $newActionArguments,
        [string]
        $oldActionArguments,
        [string]
        $newWorkingDirectory,
        [string]
        $oldWorkingDirectory
    )
    
    Import-Module ScheduledTasks
    
    
    ######################################################
    #### Main script
    ######################################################
    
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $actionsArray = $task.Actions
    
    foreach ($action in $actionsArray) {
        $argMatched = $true;
        if( -not ([string]::IsNullOrEmpty($action.Arguments) -and [string]::IsNullOrEmpty($oldActionArguments)))
        {
            if ($action.Arguments -ne $oldActionArguments)
            {
                $argMatched = $false;
            }
        }
    
        $workingDirectoryMatched  = $true;
        if( -not ([string]::IsNullOrEmpty($action.WorkingDirectory) -and [string]::IsNullOrEmpty($oldWorkingDirectory)))
        {
            if ($action.WorkingDirectory -ne $oldWorkingDirectory)
            {
                $workingDirectoryMatched = $false;
            }
        }
    
        $executeMatched  = $true;
        if ($action.Execute -ne $oldActionExecute) 
        {
              $executeMatched = $false;
        }
    
        if ($argMatched -and $executeMatched -and $workingDirectoryMatched)
        {
            $action.Execute = $newActionExecute;
            $action.Arguments = $newActionArguments;
            $action.WorkingDirectory = $newWorkingDirectory;
            break
        }
    }
    
    
    Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $actionsArray
}