<#
    
    .SYNOPSIS
        Script that check scheduled task for install updates is still running or not.
    
    .DESCRIPTION
        Script that check scheduled task for install updates is still running or not. Notcied that using the following COM object has issue: when install-WUUpdates task is running, the busy status return false;
        but right after the task finished, it returns true.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-WindowsUpdateInstallerStatus {
    Import-Module ScheduledTasks
    
    $TaskName = "SMEWindowsUpdateInstallUpdates"
    $ScheduledTask = Get-ScheduledTask | Microsoft.PowerShell.Utility\Select-Object TaskName, State | Where-Object {$_.TaskName -eq $TaskName}
    if ($ScheduledTask -ne $Null -and $ScheduledTask.State -eq 4) { # Running
        return $True
    } else {
        return $False
    }
    
}