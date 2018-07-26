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
    
    .PARAMETER username
        The username to use to run the task.
    
#>
function Set-ScheduledTaskGeneralSettings {
    param (
        [parameter(Mandatory=$true)]
        [string]
        $taskName,
        [string]
        $taskDescription,
        [parameter(Mandatory=$true)]
        [string]
        $taskPath,
        [string]
        $username
    )
    
    Import-Module ScheduledTasks
    
    ######################################################
    #### Main script
    ######################################################
    
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    if($task) {
        
        $task.Description = $taskDescription;
      
        if ($username)
        {
            $task | Set-ScheduledTask -User $username ;
        } 
        else 
        {
            $task | Set-ScheduledTask
        }
    }
}