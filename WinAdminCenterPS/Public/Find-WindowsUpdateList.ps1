<#

    .SYNOPSIS
        Create a sheduled task to run powershell script that find available or installed windows updates through COM object.

    .DESCRIPTION
        Create a sheduled task to run powershell script that find available or installed windows updates through COM object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .EXAMPLE
        # Find available windows update.
        PS C:\> Find-WindowsUpdateList "IsInstalled = 0"

    .EXAMPLE
        # Find installed windows update.
        PS C:\> Find-WindowsUpdateList "IsInstalled = 1"

    .ROLE
        Readers

#>
function Find-WindowsUpdateList {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$searchCriteria,

        [Parameter(Mandatory = $true)]
        [string]$sessionId,

        [Parameter(Mandatory = $true)]
        [int16]$serverSelection
    )

    #PowerShell script to run. In some cases, you may need use back quote (`) to treat some character (eg. double/single quate, specail escape sequence) literally.
    $Script = @'
function GenerateSearchHash($searchResults) {
    foreach ($searchResult in $searchResults){
        foreach ($KBArticleID in $searchResult.KBArticleIDs) {
            $KBID = 'KB' + $KBArticleID
            if ($KBArticleID -ne $null -and -Not $searchHash.ContainsKey($KBID)) {
                $searchHash.Add($KBID, ($searchResult | Select  msrcSeverity, title, IsMandatory))
            }
        }
    }
}

function GenerateHistoryHash($historyResults) {
    foreach ($historyResult in $historyResults){
        $KBID = ([regex]::match($historyResult.Title,'KB(\d+)')).Value.ToUpper()
        if ($KBID -ne $null -and $KBID -ne '') {
            $title = $historyResult.Title.Trim()

            if (-Not $historyHash.ContainsKey($KBID)) {
                $historyHash.Add($KBID, ($historyResult | Select  ResultCode, Date, Title))
            } elseif (($historyHash[$KBID].Title -eq $null -or $historyHash[$KBID].Title -eq '') -and ($title -ne $null -or $title.Length -gt 0)) {
                #If the previous entry did not have a title and this item has one, update it
                $historyHash[$KBID] = $historyResult | Select  ResultCode, Date, $title
            }
        }
    }
}

$objSession = New-Object -ComObject "Microsoft.Update.Session"
$objSearcher = $objSession.CreateUpdateSearcher()
$objSearcher.ServerSelection = $serverSelection
$objResults = $objSearcher.Search($searchCriteria)

$result = New-Object Collections.ArrayList

if ($searchCriteria -eq "IsInstalled=1") {
    $searchHash = @{}
    GenerateSearchHash($objResults.Updates)

    $historyCount = $objSearcher.GetTotalHistoryCount()
    $historyResults = $objSearcher.QueryHistory(0, $historyCount)

    $historyHash = @{}
    GenerateHistoryHash($historyResults)

    $installedItems = Get-Hotfix
    foreach ($installedItem in $installedItems) {
        $resultItem = $installedItem | Select HotFixID, InstalledBy
        $title = $installedItem.Description + ' (' + $resultItem.HotFixID + ')'
        $installDate = $installedItem.InstalledOn

        $titleMatch = $null

        $searchMatch = $searchHash.Item($installedItem.HotFixID)
        if ($searchMatch -ne $null) {
            $titleMatch = $searchMatch.title
            $resultItem | Add-Member -MemberType NoteProperty -Name "msrcSeverity" -Value $searchMatch.msrcSeverity
            $resultItem | Add-Member -MemberType NoteProperty -Name "IsMandatory" -Value $searchMatch.IsMandatory
        }

        $historyMatch = $historyHash.Item($installedItem.HotFixID)
        if ($historyMatch -ne $null) {
            $resultItem | Add-Member -MemberType NoteProperty -Name "installState" -Value $historyMatch.ResultCode
            if ($titleMatch -eq $null -or $titleMatch -eq '') {
                # If there was no matching title in searchMatch
                $titleMatch = $historyMatch.title
            }

            $installDate = $historyMatch.Date
        }

        if ($titleMatch -ne $null -or $titleMatch.Trim() -ne '') {
            $title = $titleMatch
        }

        $resultItem | Add-Member -MemberType NoteProperty -Name "title" -Value $title
        $resultItem | Add-Member -MemberType NoteProperty -Name "installDate" -Value $installDate

        $result.Add($resultItem)
    }
} else {
    foreach ($objResult in $objResults.Updates) {
        $resultItem = $objResult | Select msrcSeverity, title, IsMandatory
        $result.Add($resultItem)
    }
}

if(Test-Path $ResultFile)
{
    Remove-Item $ResultFile
}

$result | ConvertTo-Json -depth 10 | Out-File $ResultFile
'@

    #Pass parameters to script and generate script file in localappdata folder
    $timeStamp = Get-Date -Format FileDateTimeUniversal
    # use both ps sessionId and timestamp for file/task prefix so that multiple instances won't delete others' files and tasks
    $fileprefix = "_PS"+ $sessionId + "_Time" + $timeStamp
    $ResultFile = $env:TEMP + "\Find-Updates-result" + $fileprefix + ".json"
    $Script = '$searchCriteria = ' + "'$searchCriteria';" + '$ResultFile = ' + "'$ResultFile';" + '$serverSelection =' + "'$serverSelection';" + $Script
    $ScriptFile = $env:TEMP + "\Find-Updates" + $fileprefix + ".ps1"
    $Script | Out-File $ScriptFile
    if (-Not(Test-Path $ScriptFile)) {
        $message = "Failed to create file:" + $ScriptFile
        Write-Error $message
        return #If failed to create script file, no need continue just return here
    }

    #Create a scheduled task
    $TaskName = "SMEWindowsUpdateFindUpdates" + $fileprefix

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
                Write-EventLog -LogName Application -Source "SME Windows Updates Find Updates" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
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
    #Return result
    if(Test-Path $ResultFile)
    {
        $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
        Remove-Item $ResultFile
        return $result
    }

}
