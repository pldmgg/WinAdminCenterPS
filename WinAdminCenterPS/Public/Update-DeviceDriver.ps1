<#

    .SYNOPSIS
        Update device driver.

    .DESCRIPTION
        Update device driver.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function Update-DeviceDriver {
    param(
        $Updates 
    )

    $Script = @'
$NumberOfUpdate = 1;
$updateCount = $Updates.Count;
Foreach($Update in $Updates)
{
    Write-Progress -Activity 'Downloading updates' -Status `"[$NumberOfUpdate/$updateCount]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate/$updateCount * 100));
    $NumberOfUpdate++;
    Write-Debug `"Show` update` to` download:` $($Update.Title)`" ;
    $UpdatesToDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl';
    $UpdatesToDownload.Add($Update) | Out-Null;

    $UpdateSession = New-Object -ComObject 'Microsoft.Update.Session';
    $Downloader = $UpdateSession.CreateUpdateDownloader();
    $Downloader.Updates = $UpdatesToDownload;
    Try
    {
        Write-Debug 'Try download update';
        $DownloadResult = $Downloader.Download();
    } <#End Try#>
    Catch
    {
        If($_ -match 'HRESULT: 0x80240044')
        {
            Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
        } <#End If $_ -match 'HRESULT: 0x80240044'#>

        Return
    } <#End Catch#>

    Write-Debug 'Check ResultCode';
    Switch -exact ($DownloadResult.ResultCode)
    {
        0   { $Status = 'NotStarted'; }
        1   { $Status = 'InProgress'; }
        2   { $Status = 'Downloaded'; }
        3   { $Status = 'DownloadedWithErrors'; }
        4   { $Status = 'Failed'; }
        5   { $Status = 'Aborted'; }
    } <#End Switch#>

    If($DownloadResult.ResultCode -eq 2)
    {
        Write-Debug 'Downloaded then send update to next stage';
        $objCollectionDownload.Add($Update) | Out-Null;
    } <#End If $DownloadResult.ResultCode -eq 2#>

}

$ReadyUpdatesToInstall = $objCollectionDownload.count;
Write-Verbose `"Downloaded` [$ReadyUpdatesToInstall]` Updates` to` Install`" ;
If($ReadyUpdatesToInstall -eq 0)
{
    Return;
} <#End If $ReadyUpdatesToInstall -eq 0#>

$NeedsReboot = $false;
$NumberOfUpdate = 1;
<#install updates#>
Foreach($Update in $objCollectionDownload)
{
    Write-Progress -Activity 'Installing updates' -Status `"[$NumberOfUpdate/$ReadyUpdatesToInstall]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate/$ReadyUpdatesToInstall * 100));
    Write-Debug 'Show update to install: $($Update.Title)';

    Write-Debug 'Send update to install collection';
    $objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
    $objCollectionTmp.Add($Update) | Out-Null;

    $objInstaller = $objSession.CreateUpdateInstaller();
    $objInstaller.Updates = $objCollectionTmp;

    Try
    {
        Write-Debug 'Try install update';
        $InstallResult = $objInstaller.Install();
    } <#End Try#>
    Catch
    {
        If($_ -match 'HRESULT: 0x80240044')
        {
            Write-Warning 'Your security policy do not allow a non-administator identity to perform this task';
        } <#End If $_ -match 'HRESULT: 0x80240044'#>

        Return;
    } #End Catch

    If(!$NeedsReboot)
    {
        Write-Debug 'Set instalation status RebootRequired';
        $NeedsReboot = $installResult.RebootRequired;
    } <#End If !$NeedsReboot#>
    $NumberOfUpdate++;
} <#End Foreach $Update in $objCollectionDownload#>
'@

    #Pass parameters to script and generate script file in localappdata folder
    $ScriptFile = $env:LocalAppData + "\Install-Drivers.ps1"
    $Script = '$updates =' + $Updates + $Script
    $Script | Out-File $ScriptFile
    if (-Not(Test-Path $ScriptFile)) {
        $message = "Failed to create file:" + $ScriptFile
        Write-Error $message
        return #If failed to create script file, no need continue just return here
    }

    #Create a scheduled task
    $TaskName = "SMEWindowsUpdateInstallDrivers"

    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile"
    if(!$Role)
    {
        Write-Warning "To perform some operations you must run an elevated Windows PowerShell console."
    }

    $Scheduler = New-Object -ComObject Schedule.Service

    #Try to connect to schedule service 3 time since it may fail the first time
    for ($i=1; $i -le 3; $i++)
    {
        Try
        {
            $Scheduler.Connect()
            Break
        }
        Catch
        {
            if($i -ge 3)
            {
                Write-EventLog -LogName Application -Source "SME Windows Updates Install Updates" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
                Write-Error "Can't connect to Schedule service" -ErrorAction Stop
            }
            else
            {
                Start-Sleep -s 1
            }
        }
    }

    $RootFolder = $Scheduler.GetFolder("\")
    #Delete existing task
    if($RootFolder.GetTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Write-Debug("Deleting existing task" + $TaskName)
        $RootFolder.DeleteTask($TaskName,0)
    }

    $Task = $Scheduler.NewTask(0)
    $RegistrationInfo = $Task.RegistrationInfo
    $RegistrationInfo.Description = $TaskName
    $RegistrationInfo.Author = $User.Name

    $Triggers = $Task.Triggers
    $Trigger = $Triggers.Create(7) #TASK_TRIGGER_REGISTRATION: Starts the task when the task is registered.
    $Trigger.Enabled = $true

    $Settings = $Task.Settings
    $Settings.Enabled = $True
    $Settings.StartWhenAvailable = $True
    $Settings.Hidden = $False

    $Action = $Task.Actions.Create(0)
    $Action.Path = "powershell"
    $Action.Arguments = $arg

    #Tasks will be run with the highest privileges
    $Task.Principal.RunLevel = 1

    #Start the task to run in Local System account. 6: TASK_CREATE_OR_UPDATE
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
    #Wait for running task finished
    $RootFolder.GetTask($TaskName).Run(0) | Out-Null
    while($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Start-Sleep -s 1
    }

    #Clean up
    $RootFolder.DeleteTask($TaskName,0)
    Remove-Item $ScriptFile
}
