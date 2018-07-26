[Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"

# Get public and private function definition files.
[array]$Public  = Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" -ErrorAction SilentlyContinue
[array]$Private = Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" -ErrorAction SilentlyContinue
$ThisModule = $(Get-Item $PSCommandPath).BaseName

# Dot source the Private functions
foreach ($import in $Private) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error -Message "Failed to import function $($import.FullName): $_"
    }
}

[System.Collections.Arraylist]$ModulesToInstallAndImport = @()
if (Test-Path "$PSScriptRoot\module.requirements.psd1") {
    $ModuleManifestData = Import-PowerShellDataFile "$PSScriptRoot\module.requirements.psd1"
    $ModuleManifestData.Keys | Where-Object {$_ -ne "PSDependOptions"} | foreach {$null = $ModulesToinstallAndImport.Add($_)}
}

if ($ModulesToInstallAndImport.Count -gt 0) {
    # NOTE: If you're not sure if the Required Module is Locally Available or Externally Available,
    # add it the the -RequiredModules string array just to be certain
    $InvModDepSplatParams = @{
        RequiredModules                     = $ModulesToInstallAndImport
        InstallModulesNotAvailableLocally   = $True
        ErrorAction                         = "SilentlyContinue"
        WarningAction                       = "SilentlyContinue"
    }
    $ModuleDependenciesMap = InvokeModuleDependencies @InvModDepSplatParams
}

# Public Functions


<#
    
    .SYNOPSIS
        Gets a new share name for the folder.
    
    .DESCRIPTION
        Gets a new share name for the folder. It starts with the folder name. Then it keeps appending "2" to the name
        until the name is free. Finally return the name.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder to be shared.
    
    .PARAMETER Name
        String -- The suggested name to be shared (the folder name).
    
    .PARAMETER Force
        boolean -- override any confirmations
    
#>
function Add-FolderShare {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,    
    
        [Parameter(Mandatory = $true)]
        [String]
        $Name
    )
    
    Set-StrictMode -Version 5.0
    
    while([bool](Get-SMBShare -Name $Name -ea 0)){
        $Name = $Name + '2';
    }
    
    New-SmbShare -Name "$Name" -Path "$Path"
    @{ shareName = $Name }
    
}


<#
    
    .SYNOPSIS
        Adds a user to the folder share.
    
    .DESCRIPTION
        Adds a user to the folder share.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Name
        String -- Name of the share.
    
    .PARAMETER AccountName
        String -- The user identification (AD / Local user).
    
    .PARAMETER AccessRight
        String -- Access rights of the user.
    
#>
function Add-FolderShareNameUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,
    
        [Parameter(Mandatory = $true)]
        [String]
        $AccountName,
    
        [Parameter(Mandatory = $true)]
        [String]
        $AccessRight
    )
    
    Set-StrictMode -Version 5.0
    
    Grant-SmbShareAccess -Name "$Name" -AccountName "$AccountName" -AccessRight "$AccessRight" -Force    
}


<#
    
    .SYNOPSIS
        Adds a user access to the folder.
    
    .DESCRIPTION
        Adds a user access to the folder.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .ROLE
        Administrators

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER Path
        String -- The path to the folder.
    
    .PARAMETER Identity
        String -- The user identification (AD / Local user).
    
    .PARAMETER FileSystemRights
        String -- File system rights of the user.
    
#>
function Add-FolderShareUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
    
        [Parameter(Mandatory = $true)]
        [String]
        $FileSystemRights
    )
    
    Set-StrictMode -Version 5.0
    
    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.AddAccessRule($AccessRule)
    Set-Acl $Path $Acl
}


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
   
    .PARAMETER username
        The username associated with the trigger.
   
    .PARAMETER repetitionInterval
        The repitition interval.
   
    .PARAMETER repetitionDuration
        The repitition duration.
   
    .PARAMETER randomDelay
        The delay before running the trigger.
    
#>
function Add-ScheduledTaskTrigger {
    param (
       [parameter(Mandatory=$true)]
       [string]
       $taskName,
       [parameter(Mandatory=$true)]
       [string]
       $taskPath,
       [AllowNull()][System.Nullable[DateTime]]
       $triggerAt,
       [parameter(Mandatory=$true)]
       [string]
       $triggerFrequency, 
       [Int32]
       $daysInterval, 
       [Int32]
       $weeksInterval,
       [string[]]
       $daysOfWeek,
       [string]
       $username,
       [string]
       $repetitionInterval,
       [string]
       $repetitionDuration,
       [boolean]
       $stopAtDurationEnd,
       [string]
       $randomDelay,
       [string]
       $executionTimeLimit
   )
   
   Import-Module ScheduledTasks
   
   #
   # Prepare task trigger parameter bag
   #
   $taskTriggerParams = @{} 
   
   if ($triggerAt) {
      $taskTriggerParams.At =  $triggerAt;
   }
      
       
   # Build optional switches
   if ($triggerFrequency -eq 'Daily')
   {
       $taskTriggerParams.Daily = $true;
       if ($daysInterval -ne 0) 
       {
          $taskTriggerParams.DaysInterval = $daysInterval;
       }
   }
   elseif ($triggerFrequency -eq 'Weekly')
   {
       $taskTriggerParams.Weekly = $true;
       if ($weeksInterval -ne 0) 
       {
           $taskTriggerParams.WeeksInterval = $weeksInterval;
       }
       if ($daysOfWeek -and $daysOfWeek.Length -gt 0) 
       {
           $taskTriggerParams.DaysOfWeek = $daysOfWeek;
       }
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
   
   if ($username) 
   {
      $taskTriggerParams.User = $username;
   }
   
   
   ######################################################
   #### Main script
   ######################################################
   
   # Create trigger object
   $triggersArray = @()
   $triggerNew = New-ScheduledTaskTrigger @taskTriggerParams
   
   $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
   $triggersArray =  $task.Triggers
   
   Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggerNew | out-null
   
   $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
   $trigger = $task.Triggers[0]
   
   
   if ($repetitionInterval -and $trigger.Repetition -ne $null) 
   {
      $trigger.Repetition.Interval = $repetitionInterval;
   }
   if ($repetitionDuration -and $trigger.Repetition -ne $null) 
   {
      $trigger.Repetition.Duration = $repetitionDuration;
   }
   if ($stopAtDurationEnd -and $trigger.Repetition -ne $null) 
   {
      $trigger.Repetition.StopAtDurationEnd = $stopAtDurationEnd;
   }
   if($executionTimeLimit) {
    $task.Triggers[0].ExecutionTimeLimit = $executionTimeLimit;
   }
   
   if([bool]($task.Triggers[0].PSobject.Properties.name -eq "RandomDelay")) 
   {
       $task.Triggers[0].RandomDelay = $randomDelay;
   }
   
   if([bool]($task.Triggers[0].PSobject.Properties.name -eq "Delay")) 
   {
       $task.Triggers[0].Delay = $randomDelay;
   }
   
   $triggersArray += $trigger
   
   Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Trigger $triggersArray 
}


<#
    
    .SYNOPSIS
        Adds a local or domain user to one or more local groups.
    
    .DESCRIPTION
        Adds a local or domain user to one or more local groups. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Add-UserToLocalGroups {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName,
    
        [Parameter(Mandatory = $true)]
        [String[]]
        $GroupNames
    )
    
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    
    $ErrorActionPreference = 'Stop'
    
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    $Error.Clear()
    # Get user name or object
    $user = $null
    $objUser = $null
    if (Get-Command 'Get-LocalUser' -errorAction SilentlyContinue) {
        if ($UserName -like '*\*') { # domain user
            $user = $UserName
        } else {
            $user = Get-LocalUser -Name $UserName
        }
    } else {
        if ($UserName -like '*\*') { # domain user
            $UserName = $UserName.Replace('\', '/')
        }
        $objUser = "WinNT://$UserName,user"
    }
    # Add user to groups
    Foreach ($name in $GroupNames) {
        if (Get-Command 'Get-LocalGroup' -errorAction SilentlyContinue) {
            $group = Get-LocalGroup $name
            Add-LocalGroupMember -Group $group -Member $user
        }
        else {
            $group = $name
            try {
                $objGroup = [ADSI]("WinNT://localhost/$group,group")
                $objGroup.Add($objUser)
            }
            catch
            {
                # Append user and group name info to error message and then clear it
                $ErrMsg = $_.Exception.Message + " User: " + $UserName + ", Group: " + $group
                Write-Error $ErrMsg
                $Error.Clear()
            }
        }
    }    
}


<#
    
    .SYNOPSIS
        Clear the event log channel specified.
    
    .DESCRIPTION
        Clear the event log channel specified.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Clear-EventLogChannel { 
    Param(
        [string]$channel
    )
    
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 
}


<#
    
    .SYNOPSIS
        Clear the event log channel after export the event log channel file (.evtx).
    
    .DESCRIPTION
        Clear the event log channel after export the event log channel file (.evtx).
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Clear-EventLogChannelAfterExport {
    Param(
        [string]$channel
    )
    
    $segments = $channel.Split("-")
    $name = $segments[-1]
    
    $randomString = [GUID]::NewGuid().ToString()
    $ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
    $ResultFile = $ResultFile -replace "/", "-"
    
    wevtutil epl "$channel" "$ResultFile" /ow:true
    
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 
    
    return $ResultFile
    
}


<#
    
    .SYNOPSIS
        Compresses the specified file system entity (files, folders) of the system.
    
    .DESCRIPTION
        Compresses the specified file system entity (files, folders) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER pathSource
        String -- The path to compress.
    
    .PARAMETER PathDestination
        String -- The destination path to compress into.
    
    .PARAMETER Force
        boolean -- override any confirmations
    
#>
function Compress-ArchiveFileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $PathSource,    
    
        [Parameter(Mandatory = $true)]
        [String]
        $PathDestination,
    
        [Parameter(Mandatory = $false)]
        [boolean]
        $Force
    )
    
    Set-StrictMode -Version 5.0
    
    if ($Force) {
        Compress-Archive -Path $PathSource -Force -DestinationPath $PathDestination
    } else {
        Compress-Archive -Path $PathSource -DestinationPath $PathDestination
    }
    if ($error) {
        $code = $error[0].Exception.HResult
        @{ status = "error"; code = $code; message = $error }
    } else {
        @{ status = "ok"; }
    }    
}


<#
    
    .SYNOPSIS
        Disables Plug and Play device.
    
    .DESCRIPTION
        Disables Plug and Play device.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Disable-CimPnpEntity {
    Param(
    [string]$DeviceId
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity -Key @('DeviceId') -Property @{DeviceId=$DeviceId;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName Disable
}


<#
    
    .SYNOPSIS
        Disable Firewall Rule.
    
    .DESCRIPTION
        Disable Firewall Rule.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Disable-FirewallRule {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $instanceId,
    
        [Parameter(Mandatory = $true)]
        [String]
        $policyStore
    )
    
    Import-Module netsecurity
    
    Disable-NetFirewallRule -PolicyStore $policyStore -Name $instanceId
    
}


<#
    
    .SYNOPSIS
        Script to disable a scheduled tasks.
    
    .DESCRIPTION
        Script to disable a scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Disable-ScheduledTask {
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $true)]
      [String]
      $taskName
    )
    Import-Module ScheduledTasks
    
    Disable-ScheduledTask -TaskPath $taskPath -TaskName $taskName
    
}


<#
    .SYNOPSIS
        Detaches the VHD.
    
    .DESCRIPTION
        Detaches the VHD.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER location
        The disk location
    
#>
function Dismount-StorageVHD {
    param (
        [parameter(Mandatory=$true)]
        [String]
        $location
    )
    
    Import-Module Storage
    
    Dismount-DiskImage -ImagePath $location
}


<#
    
    .SYNOPSIS
        Edit a new firewall rule in the system.
    
    .DESCRIPTION
        Edit a new firewall rule in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Edit-FirewallRule {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $instanceId,
    
        [Parameter(Mandatory = $false)]
        [String]
        $displayName,
    
        [Parameter(Mandatory = $false)]
        [int]
        $action,
    
        [Parameter(Mandatory = $false)]
        [String]
        $description,
    
        [Parameter(Mandatory = $false)]
        [int]
        $direction,
    
        [Parameter(Mandatory = $false)]
        [bool]
        $enabled,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $icmpType,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $localPort,
    
        [Parameter(Mandatory = $false)]
        [String]
        $profile,
    
        [Parameter(Mandatory = $false)]
        [String]
        $protocol,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $remotePort
    )
    
    Import-Module netsecurity
    
    $command = 'Set-NetFirewallRule -Name $instanceId'
    if ($displayName) {
        $command += ' -NewDisplayName $displayName';
    }
    if ($action) {
        $command += ' -Action ' + $action;
    }
    if ($description) {
        $command += ' -Description $description';
    }
    if ($direction) {
        $command += ' -Direction ' + $direction;
    }
    if ($PSBoundParameters.ContainsKey('enabled')) {
        $command += ' -Enabled ' + $enabled;
    }
    if ($icmpType) {
        $command += ' -IcmpType $icmpType';
    }
    if ($localPort) {
        $command += ' -LocalPort $localPort';
    }
    if ($profile) {
        $command += ' -Profile $profile';
    }
    if ($protocol) {
        $command += ' -Protocol $protocol';
    }
    if ($remotePort) {
        $command += ' -RemotePort $remotePort';
    }
    
    Invoke-Expression $command
}


<#
    
    .SYNOPSIS
        Modifies all users' IsInherited flag to false
    
    .DESCRIPTION
        Modifies all users' IsInherited flag to false
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder.
    
#>
function Edit-FolderShareInheritanceFlag {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    $Acl = Get-Acl $Path
    $Acl.SetAccessRuleProtection($True, $True)
    Set-Acl -Path $Path -AclObject $Acl    
}


<#
    
    .SYNOPSIS
        Edits a user access to the folder.
    
    .DESCRIPTION
        Edits a user access to the folder.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder.
    
    .PARAMETER Identity
        String -- The user identification (AD / Local user).
    
    .PARAMETER FileSystemRights
        String -- File system rights of the user.
    
#>
function Edit-FolderShareUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
    
        [Parameter(Mandatory = $true)]
        [String]
        $FileSystemRights
    )
    
    Set-StrictMode -Version 5.0
    
    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.SetAccessRule($AccessRule)
    Set-Acl $Path $Acl    
}


<#
   
    .SYNOPSIS
        Update volume properties.
   
    .DESCRIPTION
        Update volume properties.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
   
    .ROLE
        Administrators
   
    .PARAMETER diskNumber
        The disk number.
   
    .PARAMETER partitionNumber
        The partition number.
   
    .PARAMETER oldDriveLetter
        Volume old dirve letter.
   
    .PARAMETER newVolumeName
        Volume new name.    
   
    .PARAMETER newDriveLetter
        Volume new dirve letter.
   
    .PARAMETER driveType
        Volume drive type.
   
#>
function Edit-StorageVolume {
    param (
       [String]
       $diskNumber,
       [uint32]
       $partitionNumber,
       [char]
       $newDriveLetter,
       [int]
       $driveType,
       [char]
       $oldDriveLetter,
       [String]
       $newVolumeName
   )
   
   Import-Module Microsoft.PowerShell.Management
   Import-Module Storage
   
   if($oldDriveLetter -ne $newDriveLetter) {
       if($driveType -eq 5 -or $driveType -eq 2)
       {
           $drv = Get-WmiObject win32_volume -filter "DriveLetter = '$($oldDriveLetter):'"
           $drv.DriveLetter = "$($newDriveLetter):"
           $drv.Put() | out-null
       } 
       else
       {
           Set-Partition -DiskNumber $diskNumber -PartitionNumber $partitionNumber -NewDriveLetter $newDriveLetter
       }
   }
   
   Set-Volume -DriveLetter $newDriveLetter -NewFileSystemLabel $newVolumeName
}


<#
    
    .SYNOPSIS
        Enables Plug and Play device.
    
    .DESCRIPTION
        Enables Plug and Play device.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Enable-CimPnpEntity {
    Param(
    [string]$DeviceId
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity -Key @('DeviceId') -Property @{DeviceId=$DeviceId;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName Enable
    
}


<#
    
    .SYNOPSIS
        Enable Firewall Rule.
    
    .DESCRIPTION
        Enable Firewall Rule.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Enable-FirewallRule {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $instanceId,
    
        [Parameter(Mandatory = $true)]
        [String]
        $policyStore
    )
    
    Import-Module netsecurity
    
    Enable-NetFirewallRule -PolicyStore $policyStore -Name $instanceId
    
}


<#
    
    .SYNOPSIS
        Script to enable a scheduled tasks.
    
    .DESCRIPTION
        Script to enable a scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Enable-ScheduledTask {
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $true)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    Enable-ScheduledTask -TaskPath $taskPath -TaskName $taskName
    
}


<#
    
    .SYNOPSIS
        Expands the specified file system entity (files, folders) of the system.
    
    .DESCRIPTION
        Expands the specified file system entity (files, folders) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER PathSource
        String -- The path to expand.
    
    .PARAMETER PathDestination
        String -- The destination path to expand into.
    
    .PARAMETER Force
        boolean -- override any confirmations
    
#>
function Expand-ArchiveFileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $PathSource,    
    
        [Parameter(Mandatory = $true)]
        [String]
        $PathDestination,
    
        [Parameter(Mandatory = $false)]
        [boolean]
        $Force
    )
    
    Set-StrictMode -Version 5.0
    
    if ($Force) {
        Expand-Archive -Path $PathSource -Force -DestinationPath $PathDestination
    } else {
        Expand-Archive -Path $PathSource -DestinationPath $PathDestination
    }
    
    if ($error) {
        $code = $error[0].Exception.HResult
        @{ status = "error"; code = $code; message = $error }
    } else {
        @{ status = "ok"; }
    }    
}


<#
    
    .SYNOPSIS
        Script that exports certificate.
    
    .DESCRIPTION
        Script that exports certificate.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Export-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $certPath,
        [Parameter(Mandatory = $true)]
        [String]
        $exportType,
        [String]
        $fileName,
        [string]
        $exportChain,
        [string]
        $exportProperties,
        [string]
        $usersAndGroups,
        [string]
        $password,
        [string]
        $invokeUserName,
        [string]
        $invokePassword
    )
    
    # Notes: invokeUserName and invokePassword are not used on this version. Remained for future use.
    
    $Script = @'
try {
    Import-Module PKI
    if ($exportChain -eq "CertificateChain")
    {
        $chainOption = "BuildChain";
    }
    else
    {
        $chainOption = "EndEntityCertOnly";
    }

    $ExportPfxCertParams = @{ Cert = $certPath; FilePath = $tempPath; ChainOption = $chainOption }
    if ($exportProperties -ne "Extended")
    {
        $ExportPfxCertParams.NoProperties = $true
    }

    if ($password)
    {
        Add-Type -AssemblyName System.Security
        $encode = new-object System.Text.UTF8Encoding
        $encrypted = [System.Convert]::FromBase64String($password)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $password = $encode.GetString($decrypted)
        $pwd = ConvertTo-SecureString -String $password -Force -AsPlainText;
        $ExportPfxCertParams.Password = $pwd
    }

    if ($usersAndGroups)
    {
        $ExportPfxCertParams.ProtectTo = $usersAndGroups
    }

    Export-PfxCertificate @ExportPfxCertParams | ConvertTo-Json -depth 10 | Out-File $ResultFile
} catch {
    $_.Exception.Message | ConvertTo-Json | Out-File $ErrorFile
}
'@
    
    function CalculateFilePath
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $exportType,
            [Parameter(Mandatory = $true)]
            [String]
            $certPath
        )
    
        $extension = $exportType.ToLower();
        if ($exportType.ToLower() -eq "cert")
        {
            $extension = "cer";
        }
    
        if (!$fileName)
        {
            $arr = $certPath.Split('\\');
            $fileName = $arr[3];
        }
    
        (Get-Childitem -Path Env:* | where-Object {$_.Name -eq "TEMP"}).value  + "\" + $fileName + "." + $extension
    }
    
    $tempPath = CalculateFilePath -exportType $exportType -certPath $certPath;
    if ($exportType -ne "Pfx")
    {
        Export-Certificate -Cert $certPath -FilePath $tempPath -Type $exportType -Force
        return;
    }
    
    # PFX private key handlings
    if ($password) {
        # encrypt password with current user.
        Add-Type -AssemblyName System.Security
        $encode = new-object System.Text.UTF8Encoding
        $bytes = $encode.GetBytes($password)
        $encrypt = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $password = [System.Convert]::ToBase64String($encrypt)
    }
    
    # Pass parameters to script and generate script file in temp folder
    $ResultFile = $env:temp + "\export-certificate_result.json"
    $ErrorFile = $env:temp + "\export-certificate_error.json"
    if (Test-Path $ErrorFile) {
        Remove-Item $ErrorFile
    }
    
    if (Test-Path $ResultFile) {
        Remove-Item $ResultFile
    }
    
    $Script = '$certPath=' + "'$certPath';" +
              '$tempPath=' + "'$tempPath';" +
              '$exportType=' + "'$exportType';" +
              '$exportChain=' + "'$exportChain';" +
              '$exportProperties=' + "'$exportProperties';" +
              '$usersAndGroups=' + "'$usersAndGroups';" +
              '$password=' + "'$password';" +
              '$ResultFile=' + "'$ResultFile';" +
              '$ErrorFile=' + "'$ErrorFile';" +
              $Script
    $ScriptFile = $env:temp + "\export-certificate.ps1"
    $Script | Out-File $ScriptFile
    
    # Create a scheduled task
    $TaskName = "SMEExportCertificate"
    
    $User = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Role = (New-Object Security.Principal.WindowsPrincipal $User).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    $arg = "-NoProfile -NoLogo -NonInteractive -ExecutionPolicy Bypass -File $ScriptFile"
    if (!$Role)
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
            if ($i -ge 3)
            {
                Write-EventLog -LogName Application -Source "SME Export certificate" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
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
    if ($RootFolder.GetTasks(0) | Where-Object {$_.Name -eq $TaskName})
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
    
    #### example Start the task with user specified invoke username and password
    ####$Task.Principal.LogonType = 1
    ####$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, $invokeUserName, $invokePassword, 1) | Out-Null
    
    #### Start the task with SYSTEM creds
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null
    #Wait for running task finished
    $RootFolder.GetTask($TaskName).Run(0) | Out-Null
    while ($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Start-Sleep -s 2
    }
    
    #Clean up
    $RootFolder.DeleteTask($TaskName,0)
    Remove-Item $ScriptFile
    #Return result
    if (Test-Path $ErrorFile) {
        $result = Get-Content -Raw -Path $ErrorFile | ConvertFrom-Json
        Remove-Item $ErrorFile
        Remove-Item $ResultFile
        throw $result
    }
    
    if (Test-Path $ResultFile)
    {
        $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
        Remove-Item $ResultFile
        return $result
    }
    
}


<#
    
    .SYNOPSIS
        Export the event log channel file (.evtx) with filter XML.
    
    .DESCRIPTION
        Export the event log channel file (.evtx) with filter XML.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Export-EventLogChannel {
    Param(
        [string]$channel,
        [string]$filterXml
    )
    
    $segments = $channel.Split("-")
    $name = $segments[-1]
    
    $randomString = [GUID]::NewGuid().ToString()
    $ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
    $ResultFile = $ResultFile -replace "/", "-"
    
    wevtutil epl "$channel" "$ResultFile" /q:"$filterXml" /ow:true
    
    return $ResultFile
    
}


<#
    
    .SYNOPSIS
        Exports registry key/values based on the selected key path.
    
    .DESCRIPTION
        Exports registry key/values based on the selected key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Export-RegistryContent {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [string]$file    
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()       
    Reg Export $path $file /y    
}


<#
    
    .SYNOPSIS
        Search drivers online.
    
    .DESCRIPTION
        Search drivers online.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Find-DeviceDrivers {
    param(
        [String]$model
    )
    
     $Session = New-Object -ComObject Microsoft.Update.Session           
     
     $Searcher = $Session.CreateUpdateSearcher() 
     $Searcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
     $Searcher.SearchScope =  1 # MachineOnly
     $Searcher.ServerSelection = 3 # Third Party
     
     $Criteria = "IsInstalled=0 and Type='Driver'"
     $SearchResult = $Searcher.Search($Criteria) 
     
     $Updates = $SearchResult.Updates          
     
     if ($model) {
        $Updates = $Updates | Where-Object {$_.driverModel -eq $model} 
     }
     
     $Updates    
}


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


<#
    
    .SYNOPSIS
        Formats a drive by drive letter.
    
    .DESCRIPTION
        Formats a drive by drive letter.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER driveLetter
        The drive letter.
    
    .PARAMETER allocationUnitSizeInBytes
        The allocation unit size.
    
    .PARAMETER fileSystem
        The file system type.
    
    .PARAMETER fileSystemLabel
        The file system label.    
    
    .PARAMETER compress
        True to compress, false otherwise.
    
    .PARAMETER quickFormat
        True to run a quick format.
#>
function Format-StorageVolume {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $driveLetter,
    
        [UInt32]
        $allocationUnitSizeInBytes,
    
        [String]
        $fileSystem,
    
        [String]
        $newFileSystemLabel,
    
        [Boolean]
        $compress = $false,
    
        [Boolean]
        $quickFormat = $true
    )
    
    Import-Module Storage
    
    #
    # Prepare parameters for command Format-Volume
    #
    $FormatVolumecmdParams = @{
        DriveLetter = $driveLetter;
        Compress = $compress;
        Full = -not $quickFormat}
    
    if($allocationUnitSizeInBytes -ne 0)
    {
        $FormatVolumecmdParams.AllocationUnitSize = $allocationUnitSizeInBytes
    }
    
    if ($fileSystem)
    {
        $FormatVolumecmdParams.FileSystem = $fileSystem
    }
    
    if ($newFileSystemLabel)
    {
        $FormatVolumecmdParams.NewFileSystemLabel = $newFileSystemLabel
    }
    
    Format-Volume @FormatVolumecmdParams -confirm:$false
    
}


<#
    .SYNOPSIS
        Gets the status of antimalware software on the computer.
    
    .DESCRIPTION
        Gets the status of antimalware software on the computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers    
#>
function Get-AntimalwareSoftwareStatus {
    if (Get-Command Get-MpComputerStatus -errorAction SilentlyContinue)
    {
        return (Get-MpComputerStatus);
    }
    else{
        return $false;
    }    
}


<#
    
    .SYNOPSIS
        Script that get windows update automatic update options from registry key.
    
    .DESCRIPTION
        Script that get windows update automatic update options from registry key.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-AutomaticUpdatesOptions {
    Import-Module Microsoft.PowerShell.Management
    
    # If there is AUOptions, return it, otherwise return NoAutoUpdate value
    $option = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorVariable myerror -ErrorAction SilentlyContinue).AUOptions
    if ($myerror) {
        $option = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ErrorVariable myerror  -ErrorAction SilentlyContinue).NoAutoUpdate
        if ($myerror) {
            $option = 0 # not defined
        }
    }
    return $option
}


<#
    
    .SYNOPSIS
        Script that get the certificates overview (total, ex) in the system.
    
    .DESCRIPTION
        Script that get the certificates overview (total, ex) in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CertificateOverview {
     param (
            [Parameter(Mandatory = $true)]
            [String]
            $channel,
            [String]
            $path = "Cert:\",
            [int]
            $nearlyExpiredThresholdInDays = 60
        )
    
    Import-Module Microsoft.PowerShell.Diagnostics -ErrorAction SilentlyContinue
    
    # Notes: $channelList must be in this format:
    #"Microsoft-Windows-CertificateServicesClient-Lifecycle-System*,Microsoft-Windows-CertificateServices-Deployment*,
    #Microsoft-Windows-CertificateServicesClient-CredentialRoaming*,Microsoft-Windows-CertificateServicesClient-Lifecycle-User*,
    #Microsoft-Windows-CAPI2*,Microsoft-Windows-CertPoleEng*"
    
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    $certCounts = New-Object -TypeName psobject
    $certs = Get-ChildLeafRecurse -pspath $path
    
    $channelList = $channel.split(",")
    $totalCount = 0
    $x = Get-WinEvent -ListLog $channelList -Force -ErrorAction 'SilentlyContinue'
    for ($i = 0; $i -le $x.Count; $i++){
        $totalCount += $x[$i].RecordCount;
    }
    
    $certCounts | add-member -Name "allCount" -Value $certs.length -MemberType NoteProperty
    $certCounts | add-member -Name "expiredCount" -Value ($certs | Where-Object {$_.NotAfter -lt [DateTime]::Now }).length -MemberType NoteProperty
    $certCounts | add-member -Name "nearExpiredCount" -Value ($certs | Where-Object { ($_.NotAfter -gt [DateTime]::Now ) -and ($_.NotAfter -lt [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays) ) }).length -MemberType NoteProperty
    $certCounts | add-member -Name "eventCount" -Value $totalCount -MemberType NoteProperty
    
    $certCounts    
}


<#
    
    .SYNOPSIS
        Script that enumerates all the certificates in the system.
    
    .DESCRIPTION
        Script that enumerates all the certificates in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-Certificates {
    param (
        [String]$path = "Cert:\",
        [int]$nearlyExpiredThresholdInDays = 60
    )
    
    <#############################################################################################
    
        Helper functions.
    
    #############################################################################################>
    
    <#
    .Synopsis
        Name: Get-ChildLeafRecurse
        Description: Recursively enumerates each scope and store in Cert:\ drive.
    
    .Parameters
        $pspath: The initial pspath to use for creating whole path to certificate store.
    
    .Returns
        The constructed ps-path object.
    #>
    function Get-ChildLeafRecurse
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
        try
        {
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{!$_.PSIsContainer} | Write-Output
        Get-ChildItem -Path $pspath -ErrorAction SilentlyContinue |?{$_.PSIsContainer} | %{
                $location = "Cert:\$($_.location)";
                if ($_.psChildName -ne $_.location)
                {
                    $location += "\$($_.PSChildName)";
                }
                Get-ChildLeafRecurse $location | % { Write-Output $_};
            }
        } catch {}
    }
    
    <#
    .Synopsis
        Name: Compute-PublicKey
        Description: Computes public key algorithm and public key parameters
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        A hashtable object of public key algorithm and public key parameters.
    #>
    function Compute-PublicKey
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $publicKeyInfo = @{}
    
        $publicKeyInfo["PublicKeyAlgorithm"] = ""
        $publicKeyInfo["PublicKeyParameters"] = ""
    
        if ($cert.PublicKey)
        {
            $publicKeyInfo["PublicKeyAlgorithm"] =  $cert.PublicKey.Oid.FriendlyName
            $publicKeyInfo["PublicKeyParameters"] = $cert.PublicKey.EncodedParameters.Format($true)
        }
    
        $publicKeyInfo
    }
    
    <#
    .Synopsis
        Name: Compute-SignatureAlgorithm
        Description: Computes signature algorithm out of original certificate object.
    
    .Parameters
        $cert: The original certificate object.
    
    .Returns
        The signature algorithm friendly name.
    #>
    function Compute-SignatureAlgorithm
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $signatureAlgorithm = [System.String]::Empty
    
        if ($cert.SignatureAlgorithm)
        {
            $signatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName;
        }
    
        $signatureAlgorithm
    }
    
    <#
    .Synopsis
        Name: Compute-PrivateKeyStatus
        Description: Computes private key exportable status.
    .Parameters
        $hasPrivateKey: A flag indicating certificate has a private key or not.
        $canExportPrivateKey: A flag indicating whether certificate can export a private key.
    
    .Returns
        Enum values "Exported" or "NotExported"
    #>
    function Compute-PrivateKeyStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $hasPrivateKey,
    
            [Parameter(Mandatory = $true)]
            [bool]
            $canExportPrivateKey
        )
    
        if (-not ($hasPrivateKey))
        {
            $privateKeystatus = "None"
        }
        else
        {
            if ($canExportPrivateKey)
            {
                $privateKeystatus = "Exportable"
            }
            else
            {
                $privateKeystatus = "NotExportable"
            }
        }
    
        $privateKeystatus
    }
    
    <#
    .Synopsis
        Name: Compute-ExpirationStatus
        Description: Computes expiration status based on notAfter date.
    .Parameters
        $notAfter: A date object refering to certificate expiry date.
    
    .Returns
        Enum values "Expired", "NearlyExpired" and "Healthy"
    #>
    function Compute-ExpirationStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [DateTime]$notAfter
        )
    
        if ([DateTime]::Now -gt $notAfter)
        {
           $expirationStatus = "Expired"
        }
        else
        {
           $nearlyExpired = [DateTime]::Now.AddDays($nearlyExpiredThresholdInDays);
    
           if ($nearlyExpired -ge $notAfter)
           {
              $expirationStatus = "NearlyExpired"
           }
           else
           {
              $expirationStatus = "Healthy"
           }
        }
    
        $expirationStatus
    }
    
    <#
    .Synopsis
        Name: Compute-ArchivedStatus
        Description: Computes archived status of certificate.
    .Parameters
        $archived: A flag to represent archived status.
    
    .Returns
        Enum values "Archived" and "NotArchived"
    #>
    function Compute-ArchivedStatus
    {
        param (
            [Parameter(Mandatory = $true)]
            [bool]
            $archived
        )
    
        if ($archived)
        {
            $archivedStatus = "Archived"
        }
        else
        {
            $archivedStatus = "NotArchived"
        }
    
        $archivedStatus
    }
    
    <#
    .Synopsis
        Name: Compute-IssuedTo
        Description: Computes issued to field out of the certificate subject.
    .Parameters
        $subject: Full subject string of the certificate.
    
    .Returns
        Issued To authority name.
    #>
    function Compute-IssuedTo
    {
        param (
            [String]
            $subject
        )
    
        $issuedTo = [String]::Empty
    
        $issuedToRegex = "CN=(?<issuedTo>[^,?]+)"
        $matched = $subject -match $issuedToRegex
    
        if ($matched -and $Matches)
        {
           $issuedTo = $Matches["issuedTo"]
        }
    
        $issuedTo
    }
    
    <#
    .Synopsis
        Name: Compute-IssuerName
        Description: Computes issuer name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The Issuer authority name.
    #>
    function Compute-IssuerName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $issuerName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    
        $issuerName
    }
    
    <#
    .Synopsis
        Name: Compute-CertificateName
        Description: Computes certificate name of certificate.
    .Parameters
        $cert: The original cert object.
    
    .Returns
        The certificate name.
    #>
    function Compute-CertificateName
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if (!$certificateName) {
            $certificateName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)
        }
    
        $certificateName
    }
    
    <#
    .Synopsis
        Name: Compute-Store
        Description: Computes certificate store name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate store name.
    #>
    function Compute-Store
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Scope
        Description: Computes certificate scope/location name.
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate scope/location name.
    #>
    function Compute-Scope
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split('\')[1].Split(':')[2]
    }
    
    <#
    .Synopsis
        Name: Compute-Path
        Description: Computes certificate path. E.g. CurrentUser\My\<thumbprint>
    .Parameters
        $pspath: The full certificate ps path of the certificate.
    
    .Returns
        The certificate path.
    #>
    function Compute-Path
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $pspath
        )
    
        $pspath.Split(':')[2]
    }
    
    
    <#
    .Synopsis
        Name: EnhancedKeyUsage-List
        Description: Enhanced KeyUsage
    .Parameters
        $cert: The original cert object.
    
    .Returns
        Enhanced Key Usage.
    #>
    function EnhancedKeyUsage-List
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $usageString = ''
        foreach ( $usage in $cert.EnhancedKeyUsageList){
           $usageString = $usageString + $usage.FriendlyName + ' ' + $usage.ObjectId + "`n"
        }
    
        $usageString
    }
    
    <#
    .Synopsis
        Name: Compute-Template
        Description: Compute template infomation of a certificate
        $certObject: The original certificate object.
    
    .Returns
        The certificate template if there is one otherwise empty string
    #>
    function Compute-Template
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $cert
        )
    
        $template = $cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if ($template) {
            $name = $template.Format(1).split('(')[0]
            if ($name) {
                $name -replace "Template="
            }
            else {
                ''
            }
        }
        else {
            ''
        }
    }
    
    <#
    .Synopsis
        Name: Extract-CertInfo
        Description: Extracts certificate info by decoding different field and create a custom object.
    .Parameters
        $certObject: The original certificate object.
    
    .Returns
        The custom object for certificate.
    #>
    function Extract-CertInfo
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.Security.Cryptography.X509Certificates.X509Certificate2]
            $certObject
        )
    
        $certInfo = @{}
    
        $certInfo["Archived"] = $(Compute-ArchivedStatus $certObject.Archived)
        $certInfo["CertificateName"] = $(Compute-CertificateName $certObject)
    
        $certInfo["EnhancedKeyUsage"] = $(EnhancedKeyUsage-List $certObject) #new
        $certInfo["FriendlyName"] = $certObject.FriendlyName
        $certInfo["IssuerName"] = $(Compute-IssuerName $certObject)
        $certInfo["IssuedTo"] = $(Compute-IssuedTo $certObject.Subject)
        $certInfo["Issuer"] = $certObject.Issuer #new
    
        $certInfo["NotAfter"] = $certObject.NotAfter
        $certInfo["NotBefore"] = $certObject.NotBefore
    
        $certInfo["Path"] = $(Compute-Path  $certObject.PsPath)
        $certInfo["PrivateKey"] =  $(Compute-PrivateKeyStatus -hasPrivateKey $certObject.CalculatedHasPrivateKey -canExportPrivateKey  $certObject.CanExportPrivateKey)
        $publicKeyInfo = $(Compute-PublicKey $certObject)
        $certInfo["PublicKey"] = $publicKeyInfo.PublicKeyAlgorithm
        $certInfo["PublicKeyParameters"] = $publicKeyInfo.PublicKeyParameters
    
        $certInfo["Scope"] = $(Compute-Scope  $certObject.PsPath)
        $certInfo["Store"] = $(Compute-Store  $certObject.PsPath)
        $certInfo["SerialNumber"] = $certObject.SerialNumber
        $certInfo["Subject"] = $certObject.Subject
        $certInfo["Status"] =  $(Compute-ExpirationStatus $certObject.NotAfter)
        $certInfo["SignatureAlgorithm"] = $(Compute-SignatureAlgorithm $certObject)
    
        $certInfo["Thumbprint"] = $certObject.Thumbprint
        $certInfo["Version"] = $certObject.Version
    
        $certInfo["Template"] = $(Compute-Template $certObject)
    
        $certInfo
    }
    
    
    <#############################################################################################
    
        Main script.
    
    #############################################################################################>
    
    
    $certificates =  @()
    
    Get-ChildLeafRecurse $path | foreach {
        $cert = $_
        $cert | Add-Member -Force -NotePropertyName "CalculatedHasPrivateKey" -NotePropertyValue $_.HasPrivateKey
        $exportable = $false
    
        if ($cert.HasPrivateKey)
        {
            [System.Security.Cryptography.CspParameters] $cspParams = new-object System.Security.Cryptography.CspParameters
            $contextField = $cert.GetType().GetField("m_safeCertContext", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance)
            $privateKeyMethod = $cert.GetType().GetMethod("GetPrivateKeyInfo", [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static)
            if ($contextField -and $privateKeyMethod) {
            $contextValue = $contextField.GetValue($cert)
            $privateKeyInfoAvailable = $privateKeyMethod.Invoke($cert, @($ContextValue, $cspParams))
            if ($privateKeyInfoAvailable)
            {
                $PrivateKeyCount++
                $csp = new-object System.Security.Cryptography.CspKeyContainerInfo -ArgumentList @($cspParams)
                if ($csp.Exportable)
                {
                    $exportable = $true
                }
            }
            }
            else
            {
                    $exportable = $true
            }
        }
    
        $cert | Add-Member -Force -NotePropertyName "CanExportPrivateKey" -NotePropertyValue $exportable
    
        $certificates += Extract-CertInfo $cert
    
        }
    
    $certificates
    
}


<#
    
    .SYNOPSIS
        Script that enumerates all the certificate scopes/locations in the system.
    
    .DESCRIPTION
        Script that enumerates all the certificate scopes/locations in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CertificateScopes {
    Get-ChildItem | Microsoft.PowerShell.Utility\Select-Object -Property @{name ="Name";expression= {$($_.LocationName)}}    
}


<#
    
    .SYNOPSIS
        Script that enumerates all the certificate stores in the system inside the scope/location.
    
    .DESCRIPTION
        Script that enumerates all the certificate stores in the system inside the scope/location.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CertificateStores {
    Param([string]$scope)
    Get-ChildItem $('Cert:' + $scope) | Microsoft.PowerShell.Utility\Select-Object Name, @{
        name ="Path"
        expression= {$($_.Location.toString() + '\' + $_.Name)}
    }
}


<#
    
    .SYNOPSIS
        Script that enumerates all the certificate scopes/locations in the system.
    
    .DESCRIPTION
        Script that enumerates all the certificate scopes/locations in the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CertificateTreeNodes {
    $treeNodes = @()
    $treeNodes = Get-ChildItem $('Cert:\localMachine') | Microsoft.PowerShell.Utility\Select-Object Name, @{name ="Path";expression= {$($_.Location.toString() + '\' + $_.Name)}}
    $treeNodes += Get-ChildItem $('Cert:\currentuser') | Microsoft.PowerShell.Utility\Select-Object Name, @{name ="Path";expression= {$($_.Location.toString() + '\' + $_.Name)}}
    $treeNodes   
}


<#
    
    .SYNOPSIS
        Gets CIM class for Win32_PnPEntity
    
    .DESCRIPTION
        Gets CIM class for Win32_PnPEntity

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimClassPnpEntity {
    Import-Module CimCmdlets
    
    Get-CimClass -Class "Win32_PnPEntity"   
}


<#
    
    .SYNOPSIS
        Get Log records of event channel by using Server Manager CIM provider.
    
    .DESCRIPTION
        Get Log records of event channel by using Server Manager CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimEventLogRecords {
    Param(
        [string]$FilterXml,
        [bool]$ReverseDirection
    )
    
    import-module CimCmdlets
    
    $machineName = [System.Net.DNS]::GetHostByName('').HostName
    Invoke-CimMethod -Namespace root/Microsoft/Windows/ServerManager -ClassName MSFT_ServerManagerTasks -MethodName GetServerEventDetailEx -Arguments @{
        FilterXml = $FilterXml
        ReverseDirection = $ReverseDirection
    } | ForEach-Object {
        $result = $_
        if ($result.PSObject.Properties.Match('ItemValue').Count) {
            foreach ($item in $result.ItemValue) {
                @{
                    ItemValue = @{
                        Description  = $item.description
                        Id           = $item.id
                        Level        = $item.level
                        Log          = $item.log
                        Source       = $item.source
                        Timestamp    = $item.timestamp
                        __ServerName = $machineName
                    }
                }
            }
        }
    }
}


<#
    .SYNOPSIS
        Get Memory summary by using ManagementTools CIM provider.
    
    .DESCRIPTION
        Get Memory summary by using ManagementTools CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-CimMemorySummary {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTMemorySummary
}


<#
    
    .SYNOPSIS
        Gets Namespace information under root/Microsoft/Windows
    
    .DESCRIPTION
        Gets Namespace information under root/Microsoft/Windows

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimNamespaceWithinMicrosoftWindows {
    Param(
    )
    
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/Microsoft/Windows -Query "SELECT * FROM __NAMESPACE"    
}


<#
    
    .SYNOPSIS
        Get Network Adapter summary by using ManagementTools CIM provider.
    
    .DESCRIPTION
        Get Network Adapter summary by using ManagementTools CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimNetworkAdapterSummary {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTNetworkAdapter   
}


<#
    
    .SYNOPSIS
        Get Plug and Play device instances by using CIM provider.
    
    .DESCRIPTION
        Get Plug and Play device instances by using CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimPnpEntity {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity   
}


<#
    
    .SYNOPSIS
        Gets Plug and Play device device properties.
    
    .DESCRIPTION
        Gets Plug and Play device device properties.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimPnpEntityDeviceProperties {
    Param(
    [string]$DeviceId
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_PnPEntity -Key @('DeviceId') -Property @{DeviceId=$DeviceId;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName GetDeviceProperties
}


<#
    
    .SYNOPSIS
        Get Plug and Play instance for a specifice device by using CIM provider.
    
    .DESCRIPTION
        Get Plug and Play instance for a specifice device by using CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimPnpEntityForDevice {
    Param(
    [string]$DeviceId
    )
    
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -Query "select * from Win32_PnPEntity where DeviceID='$DeviceId'"
}


<#
    
    .SYNOPSIS
        Get Pnp signed driver by using CIM provider.
    
    .DESCRIPTION
        Get Pnp signed driver by using CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimPnpSignedDriver {
    Param(
    [string]$DeviceId
    )
    
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -Query "select * from Win32_PnPSignedDriver where DeviceID='$DeviceId'"    
}


<#
    
    .SYNOPSIS
        Gets Msft_MTProcess objects.
    
    .DESCRIPTION
        Gets Msft_MTProcess objects.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimProcess {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcess
}


<#
    
    .SYNOPSIS
        Get Processor summary by using ManagementTools CIM provider.
    
    .DESCRIPTION
        Get Processor summary by using ManagementTools CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers
    
#>
function Get-CimProcessorSummary {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcessorSummary
}


<#
    
    .SYNOPSIS
        Gets Registry Sub Keys.
    
    .DESCRIPTION
        Gets Registry Sub Keys.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimRegistrySubKeys {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/microsoft/windows/managementtools -ClassName MSFT_MTRegistryKey -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName GetSubKeys   
}


<#
    
    .SYNOPSIS
        Gets Registry Values on a registry key.
    
    .DESCRIPTION
        Gets Registry Values on a registry key.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimRegistryValues {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/microsoft/windows/managementtools -ClassName MSFT_MTRegistryKey -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName GetValues
    
}


<#
    
    .SYNOPSIS
        Gets services in details using MSFT_ServerManagerTasks class.
    
    .DESCRIPTION
        Gets services in details using MSFT_ServerManagerTasks class.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimServiceDetail {
    Param(
    )
    
    import-module CimCmdlets
    
    Invoke-CimMethod -Namespace root/microsoft/windows/servermanager -ClassName MSFT_ServerManagerTasks -MethodName GetServerServiceDetail
}


<#
    
    .SYNOPSIS
        Gets the service instance of CIM Win32_Service class.
    
    .DESCRIPTION
        Gets the service instance of CIM Win32_Service class.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimSingleService {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Get-CimInstance $keyInstance
    
}


<#
    .SYNOPSIS
        Gets Win32_ComputerSystem object.
    
    .DESCRIPTION
        Gets Win32_ComputerSystem object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimWin32ComputerSystem {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_ComputerSystem
}


<#
    .SYNOPSIS
        Gets Win32_LogicalDisk object.
    
    .DESCRIPTION
        Gets Win32_LogicalDisk object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-CimWin32LogicalDisk {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_LogicalDisk
}


<#
    .SYNOPSIS
        Gets Win32_NetworkAdapter object.
    
    .DESCRIPTION
        Gets Win32_NetworkAdapter object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-CimWin32NetworkAdapter {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_NetworkAdapter    
}


<#
    .SYNOPSIS
        Gets Win32_OperatingSystem object.
    
    .DESCRIPTION
        Gets Win32_OperatingSystem object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-CimWin32OperatingSystem {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_OperatingSystem
}


<#
    .SYNOPSIS
        Gets Win32_PhysicalMemory object.
    
    .DESCRIPTION
        Gets Win32_PhysicalMemory object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-CimWin32PhysicalMemory {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PhysicalMemory
}


<#    
    .SYNOPSIS
        Gets Win32_Processor object.
    
    .DESCRIPTION
        Gets Win32_Processor object.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-CimWin32Processor {
    import-module CimCmdlets
    
    Get-CimInstance -Namespace root/cimv2 -ClassName Win32_Processor
}


<#
    
    .SYNOPSIS
        Gets status of the connection to the client computer.
    
    .DESCRIPTION
        Gets status of the connection to the client computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ClientConnectionStatus {
    import-module CimCmdlets
    $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    $Caption = $OperatingSystem.Caption
    $ProductType = $OperatingSystem.ProductType
    $Version = $OperatingSystem.Version
    $Status = @{ Label = $null; Type = 0; Details = $null; }
    $Result = @{ Status = $Status; Caption = $Caption; ProductType = $ProductType; Version = $Version; }
    
    if ($Version -and $ProductType -eq 1) {
        $V = [version]$Version
        $V10 = [version]'10.0'
        if ($V -ge $V10) {
            return $Result;
        } 
    }
    
    $Status.Label = 'unsupported-label'
    $Status.Type = 3
    $Status.Details = 'unsupported-details'
    return $Result;
    
}


<#
    .SYNOPSIS
        Retrieves the inventory data for a cluster.
    
    .DESCRIPTION
        Retrieves the inventory data for a cluster.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ClusterInventory {
    import-module CimCmdlets
    
    # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
    import-module FailoverClusters -ErrorAction SilentlyContinue
    
    <#
        .SYNOPSIS
        Get the name of this computer.
        
        .DESCRIPTION
        Get the best available name for this computer.  The FQDN is preferred, but when not avaialble
        the NetBIOS name will be used instead.
    #>
    function getComputerName() {
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, DNSHostName
    
        if ($computerSystem) {
            $computerName = $computerSystem.DNSHostName
    
            if ($computerName -eq $null) {
                $computerName = $computerSystem.Name
            }
    
            return $computerName
        }
    
        return $null
    }
    
    <#
        .SYNOPSIS
        Are the cluster PowerShell cmdlets installed on this server?
        
        .DESCRIPTION
        Are the cluster PowerShell cmdlets installed on this server?
    #>
    function getIsClusterCmdletAvailable() {
        $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue
    
        return !!$cmdlet
    }
    
    <#
        .SYNOPSIS
        Get the MSCluster Cluster CIM instance from this server.
        
        .DESCRIPTION
        Get the MSCluster Cluster CIM instance from this server.
    #>
    function getClusterCimInstance() {
        $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
        if ($namespace) {
            return Get-CimInstance -Namespace root/mscluster MSCluster_Cluster -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object fqdn, S2DEnabled
        }
    
        return $null
    }
    
    <#
        .SYNOPSIS
        Get some basic information about the cluster from the cluster.
        
        .DESCRIPTION
        Get the needed cluster properties from the cluster.
    #>
    function getClusterInfo() {
        $returnValues = @{}
    
        $returnValues.Fqdn = $null
        $returnValues.isS2DEnabled = $false
    
        $cluster = getClusterCimInstance
        if ($cluster) {
            $returnValues.Fqdn = $cluster.fqdn
            $returnValues.isS2DEnabled = ($cluster.S2DEnabled -eq 1)
        }
    
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Are the cluster PowerShell Health cmdlets installed on this server?
        
        .DESCRIPTION
        Are the cluster PowerShell Health cmdlets installed on this server?
    #>
    function getisClusterHealthCmdletAvailable() {
        $cmdlet = Get-Command -Name "Get-HealthFault" -ErrorAction SilentlyContinue
    
        return !!$cmdlet
    }
    <#
        .SYNOPSIS
        Are the Britannica (sddc management resources) available on the cluster?
        
        .DESCRIPTION
        Are the Britannica (sddc management resources) available on the cluster?
    #>
    function getIsBritannicaEnabled() {
        return (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue) `
            -ne $null
    }
    
    <#
        .SYNOPSIS
        Are the Britannica (sddc management resources) virtual machine available on the cluster?
        
        .DESCRIPTION
        Are the Britannica (sddc management resources) virtual machine available on the cluster?
    #>
    function getIsBritannicaVirtualMachineEnabled() {
        return (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue) `
            -ne $null
    }
    
    <#
        .SYNOPSIS
        Are the Britannica (sddc management resources) virtual switch available on the cluster?
        
        .DESCRIPTION
        Are the Britannica (sddc management resources) virtual switch available on the cluster?
    #>
    function getIsBritannicaVirtualSwitchEnabled() {
        return (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualSwitch -ErrorAction SilentlyContinue) `
            -ne $null
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    $clusterInfo = getClusterInfo
    
    $result = New-Object PSObject
    
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $clusterInfo.Fqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsS2DEnabled' -Value $clusterInfo.isS2DEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsClusterHealthCmdletAvailable' -Value (getIsClusterHealthCmdletAvailable)
    $result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value (getIsBritannicaEnabled)
    $result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualMachineEnabled' -Value (getIsBritannicaVirtualMachineEnabled)
    $result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualSwitchEnabled' -Value (getIsBritannicaVirtualSwitchEnabled)
    $result | Add-Member -MemberType NoteProperty -Name 'IsClusterCmdletAvailable' -Value (getIsClusterCmdletAvailable)
    $result | Add-Member -MemberType NoteProperty -Name 'CurrentClusterNode' -Value (getComputerName)
    
    $result
    
}


<#
    .SYNOPSIS
        Retrieves the inventory data for cluster nodes in a particular cluster.
    
    .DESCRIPTION
        Retrieves the inventory data for cluster nodes in a particular cluster.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ClusterNodes {
    import-module CimCmdlets
    
    # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
    import-module FailoverClusters -ErrorAction SilentlyContinue
    
    <#
        .SYNOPSIS
        Are the cluster PowerShell cmdlets installed?
        
        .DESCRIPTION
        Use the Get-Command cmdlet to quickly test if the cluster PowerShell cmdlets
        are installed on this server.
    #>
    function getClusterPowerShellSupport() {
        $cmdletInfo = Get-Command 'Get-ClusterNode' -ErrorAction SilentlyContinue
    
        return $cmdletInfo -and $cmdletInfo.Name -eq "Get-ClusterNode"
    }
    
    <#
        .SYNOPSIS
        Get the cluster nodes using the cluster CIM provider.
        
        .DESCRIPTION
        When the cluster PowerShell cmdlets are not available fallback to using
        the cluster CIM provider to get the needed information.
    #>
    function getClusterNodeCimInstances() {
        # Change the WMI property NodeDrainStatus to DrainStatus to match the PS cmdlet output.
        return Get-CimInstance -Namespace root/mscluster MSCluster_Node -ErrorAction SilentlyContinue | `
            Microsoft.PowerShell.Utility\Select-Object @{Name="DrainStatus"; Expression={$_.NodeDrainStatus}}, DynamicWeight, Name, NodeWeight, FaultDomain, State
    }
    
    <#
        .SYNOPSIS
        Get the cluster nodes using the cluster PowerShell cmdlets.
        
        .DESCRIPTION
        When the cluster PowerShell cmdlets are available use this preferred function.
    #>
    function getClusterNodePsInstances() {
        return Get-ClusterNode -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object DrainStatus, DynamicWeight, Name, NodeWeight, FaultDomain, State
    }
    
    <#
        .SYNOPSIS
        Use DNS services to get the FQDN of the cluster NetBIOS name.
        
        .DESCRIPTION
        Use DNS services to get the FQDN of the cluster NetBIOS name.
        
        .Notes
        It is encouraged that the caller add their approprate -ErrorAction when
        calling this function.
    #>
    function getClusterNodeFqdn($clusterNodeName) {
        return  ([System.Net.Dns]::GetHostEntry($clusterNodeName)).HostName
    }
    
    <#
        .SYNOPSIS
        Get the cluster nodes.
        
        .DESCRIPTION
        When the cluster PowerShell cmdlets are available get the information about the cluster nodes
        using PowerShell.  When the cmdlets are not available use the Cluster CIM provider.
    #>
    function getClusterNodes() {
        $isClusterCmdletAvailable = getClusterPowerShellSupport
    
        if ($isClusterCmdletAvailable) {
            $clusterNodes = getClusterNodePsInstances
        } else {
            $clusterNodes = getClusterNodeCimInstances
        }
    
        $clusterNodeMap = @{}
    
        foreach ($clusterNode in $clusterNodes) {
            $clusterNodeName = $clusterNode.Name.ToLower()
            $clusterNodeFqdn = getClusterNodeFqdn $clusterNodeName -ErrorAction SilentlyContinue
    
            $clusterNodeResult = New-Object PSObject
    
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FullyQualifiedDomainName' -Value $clusterNodeFqdn
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'Name' -Value $clusterNodeName
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DynamicWeight' -Value $clusterNode.DynamicWeight
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'NodeWeight' -Value $clusterNode.NodeWeight
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FaultDomain' -Value $clusterNode.FaultDomain
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'State' -Value $clusterNode.State
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DrainStatus' -Value $clusterNode.DrainStatus
    
            $clusterNodeMap.Add($clusterNodeName, $clusterNodeResult)
        }
    
        return $clusterNodeMap
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    getClusterNodes
    
}


<#
    
    .SYNOPSIS
        Gets the local computer domain/workplace information.
    
    .DESCRIPTION
        Gets the local computer domain/workplace information.
        Returns the computer identification information.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ComputerIdentification {
    import-module CimCmdlets
    
    $ComputerSystem = Get-CimInstance -Class Win32_ComputerSystem;
    $ComputerName = $ComputerSystem.DNSHostName
    if ($ComputerName -eq $null) {
        $ComputerName = $ComputerSystem.Name
    }
    
    $fqdn = ([System.Net.Dns]::GetHostByName($ComputerName)).HostName
    
    $ComputerSystem | Microsoft.PowerShell.Utility\Select-Object `
    @{ Name = "ComputerName"; Expression = { $ComputerName }},
    @{ Name = "Domain"; Expression = { if ($_.PartOfDomain) { $_.Domain } else { $null } }},
    @{ Name = "DomainJoined"; Expression = { $_.PartOfDomain }},
    @{ Name = "FullComputerName"; Expression = { $fqdn }},
    @{ Name = "Workgroup"; Expression = { if ($_.PartOfDomain) { $null } else { $_.Workgroup } }}    
}


<#
    
    .SYNOPSIS
        Gets the computer name.
    
    .DESCRIPTION
        Gets the compuiter name.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-ComputerName {
    Set-StrictMode -Version 5.0
    
    $ComputerName = $env:COMPUTERNAME
    @{ computerName = $ComputerName }
}


<#
    
    .SYNOPSIS
        Get information about the driver inf file
    
    .DESCRIPTION
        Get information about the driver inf file

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-DeviceDriverInformation {
    param(
        [String]$path,
        [bool]$recursive,
        [String]$classguid
    )
    
    $driversCollection = (Get-ChildItem -Path "$path" -Filter "*.inf" -recurse:$recursive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Fullname)
    
    Foreach ($Driver in $driversCollection)
    {
        $GUID = ""
        $Version = ""
        $Provider = ""
    
        $content = Get-Content -Path "$Driver"
    
        $line = ($content  | Select-String "ClassGuid")
        if ($line -ne $null) {
            $GUID = $line.Line.Split('=')[-1].Split(' ').Split(';')
            $GUID = ([string]$GUID).trim()
        }
    
        $line = ($content  | Select-String "DriverVer")
        if ($line -ne $null) {
            $Version = $line.Line.Split('=')[-1].Split(' ').Split(';')
            $Version = ([string]$Version).trim()
        }
       
        $line = ($content  | Select-String "Provider")
        if ($line -ne $null) {
            $Provider = $line.Line.Split('=')[-1].Split(' ').Split(';')
            $Provider = ([string]$Provider).trim()
        }
    
        if ($classguid -eq $GUID){
            Write-Output "$Driver,$Provider,$Version,$GUID"
        }
    }    
}


<#
    
    .SYNOPSIS
        Get Disk summary by using ManagementTools CIM provider.
    
    .DESCRIPTION
        Get Disk summary by using ManagementTools CIM provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-DiskSummary {
    import-module CimCmdlets
    
    $ReadResult = (get-itemproperty -path HKLM:\SYSTEM\CurrentControlSet\Services\partmgr -Name EnableCounterForIoctl -ErrorAction SilentlyContinue)
    if (!$ReadResult -or $ReadResult.EnableCounterForIoctl -ne 1) {
        # no disk performance counters enabled.
        return
    }
    
    $instances = Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTDisk
    if ($instances -ne $null) {
        $instances | ForEach-Object {
            $instance = ($_ | Microsoft.PowerShell.Utility\Select-Object ActiveTime, AverageResponseTime, Capacity, CurrentIndex, DiskNumber, IntervalSeconds, Name, ReadTransferRate, WriteTransferRate)
            $volumes = ($_.Volumes | Microsoft.PowerShell.Utility\Select-Object FormattedSize, PageFile, SystemDisk, VolumePath)
            $instance | Add-Member -NotePropertyName Volumes -NotePropertyValue $volumes
            $instance
        }
    }    
}


<#
    
    .SYNOPSIS
        Gets disk summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets disk summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-DiskSummaryDownlevel {
    param
    (
    )
    
    import-module CimCmdlets
    
    function ResetDiskData($diskResults) {
        $Global:DiskResults = @{}
        $Global:DiskDelta = 0
    
        foreach ($item in $diskResults) {
            $diskRead = New-Object System.Collections.ArrayList
            $diskWrite = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt 60; $i++) {
                $diskRead.Insert(0, 0)
                $diskWrite.Insert(0, 0)
            }
    
            $Global:DiskResults.Item($item.name) = @{
                ReadTransferRate  = $diskRead
                WriteTransferRate = $diskWrite
            }
        }
    }
    
    function UpdateDiskData($diskResults) {
        $Global:DiskDelta += ($Global:DiskSampleTime - $Global:DiskLastTime).TotalMilliseconds
    
        foreach ($diskResult in $diskResults) {
            $localDelta = $Global:DiskDelta
    
            # update data for each disk
            $item = $Global:DiskResults.Item($diskResult.name)
    
            if ($item -ne $null) {
                while ($localDelta -gt 1000) {
                    $localDelta -= 1000
                    $item.ReadTransferRate.Insert(0, $diskResult.DiskReadBytesPersec)
                    $item.WriteTransferRate.Insert(0, $diskResult.DiskWriteBytesPersec)
                }
    
                $item.ReadTransferRate = $item.ReadTransferRate.GetRange(0, 60)
                $item.WriteTransferRate = $item.WriteTransferRate.GetRange(0, 60)
    
                $Global:DiskResults.Item($diskResult.name) = $item
            }
        }
    
        $Global:DiskDelta = $localDelta
    }
    
    $counterValue = Get-CimInstance win32_perfFormattedData_PerfDisk_PhysicalDisk -Filter "name!='_Total'" | Microsoft.PowerShell.Utility\Select-Object name, DiskReadBytesPersec, DiskWriteBytesPersec
    $now = get-date
    
    # get sampling time and remember last sample time.
    if (-not $Global:DiskSampleTime) {
        $Global:DiskSampleTime = $now
        $Global:DiskLastTime = $Global:DiskSampleTime
        ResetDiskData($counterValue)
    }
    else {
        $Global:DiskLastTime = $Global:DiskSampleTime
        $Global:DiskSampleTime = $now
        if ($Global:DiskSampleTime - $Global:DiskLastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            ResetDiskData($counterValue)
        }
        else {
            UpdateDiskData($counterValue)
        }
    }
    
    $Global:DiskResults
}


<#
    
    .SYNOPSIS
        Gets 'Machine' and 'User' environment variables.
    
    .DESCRIPTION
        Gets 'Machine' and 'User' environment variables.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-EnvironmentVariables {
    Set-StrictMode -Version 5.0
    
    $data = @()
    
    $system = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::Machine)
    $user = [Environment]::GetEnvironmentVariables([EnvironmentVariableTarget]::User)
    
    foreach ($h in $system.GetEnumerator()) {
        $obj = @{"Name" = $h.Name; "Value" = $h.Value; "Type" = "Machine"}
        $data += $obj
    }
    
    foreach ($h in $user.GetEnumerator()) {
        $obj = @{"Name" = $h.Name; "Value" = $h.Value; "Type" = "User"}
        $data += $obj
    }
    
    $data
}


<#
   
    .SYNOPSIS
        Change the current status (Enabled/Disabled) for the selected channel.
   
    .DESCRIPTION
        Change the current status (Enabled/Disabled) for the selected channel.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
   
    .ROLE
        Administrators
   
#>
function Set-EventLogChannelStatus {
   Param(
       [string]$channel,
       [boolean]$status
   )
   
   $ch = Get-WinEvent -ListLog $channel
   $ch.set_IsEnabled($status)
   $ch.SaveChanges()
}


<#
    
    .SYNOPSIS
        Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.
    
    .DESCRIPTION
        Get the total amout of events that meet the filters selected by using Get-WinEvent cmdlet.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-EventLogFilteredCount {
    Param(
        [string]$filterXml
    )
    
    return (Get-WinEvent -FilterXml "$filterXml" -ErrorAction 'SilentlyContinue').count
}


<#
    
    .SYNOPSIS
        Get Log records of event channel by using Get-WinEvent cmdlet.
    
    .DESCRIPTION
        Get Log records of event channel by using Get-WinEvent cmdlet.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers

#>
function Get-EventLogRecords {
    Param(
        [string]
        $filterXml,
        [bool]
        $reverseDirection
    )
    
    $ErrorActionPreference = 'SilentlyContinue'
    Import-Module Microsoft.PowerShell.Diagnostics;
    
    #
    # Prepare parameters for command Get-WinEvent
    #
    $winEventscmdParams = @{
        FilterXml = $filterXml;
        Oldest    = !$reverseDirection;
    }
    
    Get-WinEvent  @winEventscmdParams -ErrorAction SilentlyContinue | Select recordId,
    id, 
    @{Name = "Log"; Expression = {$_."logname"}}, 
    level, 
    timeCreated, 
    machineName, 
    @{Name = "Source"; Expression = {$_."ProviderName"}}, 
    @{Name = "Description"; Expression = {$_."Message"}}    
}


<#
    
    .SYNOPSIS
        Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
    
    .DESCRIPTION
        Get the log summary (Name, Total) for the channel selected by using Get-WinEvent cmdlet.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-EventLogSummary {
    Param(
        [string]$channel
    )
    
    $ErrorActionPreference = 'SilentlyContinue'
    
    Import-Module Microsoft.PowerShell.Diagnostics;
    
    $channelList = $channel.split(",")
    
    Get-WinEvent -ListLog $channelList -Force -ErrorAction SilentlyContinue
}


<#
    
    .SYNOPSIS
        Enumerates all of the file system entities (files, folders, volumes) of the system.
    
    .DESCRIPTION
        Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .ROLE
        Readers

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER Path
        String -- The path to enumerate.
    
    .PARAMETER OnlyFolders
        switch -- 
    
#>
function Get-FileNamesInPath {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $false)]
        [switch]
        $OnlyFolders
    )
    
    Set-StrictMode -Version 5.0
    
    function isFolder($item) {
        return $item.Attributes -match "Directory" -or $item.Attributes -match "ReparsePoint"
    }
    
    function getName($item) {
        $slash = '';
    
        if (isFolder $item) {
            $slash = '\';
        }
    
        return "$($_.Name)$slash"
    }
    
    if ($onlyFolders) {
        return (Get-ChildItem -Path $Path | Where-Object {isFolder $_}) | ForEach-Object { return "$($_.Name)\"} | Sort-Object
    }
    
    return (Get-ChildItem -Path $Path) | ForEach-Object { return getName($_)} | Sort-Object
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the file system entities (files, folders, volumes) of the system.
    
    .DESCRIPTION
        Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER Path
        String -- The path to enumerate.
    
    .PARAMETER OnlyFiles
        switch -- 
    
    .PARAMETER OnlyFolders
        switch -- 
    
#>
function Get-FileSystemEntities {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $false)]
        [Switch]
        $OnlyFiles,
    
        [Parameter(Mandatory = $false)]
        [Switch]
        $OnlyFolders
    )
    
    Set-StrictMode -Version 5.0
    
    <#
    .Synopsis
        Name: Get-FileSystemEntities
        Description: Gets all the local file system entities of the machine.
    
    .Parameter Path
        String -- The path to enumerate.
    
    .Returns
        The local file system entities.
    #>
    function Get-FileSystemEntities
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $Path
        )
    
        return Get-ChildItem -Path $Path -Force |
            Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                            @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                            Extension,
                            @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                            Name,
                            @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                            @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                            @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};
    }
    
    <#
    .Synopsis
        Name: Get-FileSystemEntityType
        Description: Gets the type of a local file system entity.
    
    .Parameter Attributes
        The System.IO.FileAttributes of the FileSystemEntity.
    
    .Returns
        The type of the local file system entity.
    #>
    function Get-FileSystemEntityType
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.IO.FileAttributes]
            $Attributes
        )
    
        if ($Attributes -match "Directory" -or $Attributes -match "ReparsePoint")
        {
            return "Folder";
        }
        else
        {
            return "File";
        }
    }
    
    $entities = Get-FileSystemEntities -Path $Path;
    if ($OnlyFiles -and $OnlyFolders)
    {
        return $entities;
    }
    
    if ($OnlyFiles)
    {
        return $entities | Where-Object { $_.Type -eq "File" };
    }
    
    if ($OnlyFolders)
    {
        return $entities | Where-Object { $_.Type -eq "Folder" };
    }
    
    return $entities;
    
}


<#
    
    .SYNOPSIS
        Enumerates the root of the file system (volumes and related entities) of the system.
    
    .DESCRIPTION
        Enumerates the root of the file system (volumes and related entities) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-FileSystemRoot {
    Set-StrictMode -Version 5.0
    import-module CimCmdlets
    
    <#
    .Synopsis
        Name: Get-FileSystemRoot
        Description: Gets the local file system root entities of the machine.
    
    .Returns
        The local file system root entities.
    #>
    function Get-FileSystemRoot
    {
        $volumes = Enumerate-Volumes;
    
        return $volumes |
            Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.DriveLetter +":\"}},
                            @{Name="CreationDate"; Expression={$null}},
                            @{Name="Extension"; Expression={$null}},
                            @{Name="IsHidden"; Expression={$false}},
                            @{Name="Name"; Expression={if ($_.FileSystemLabel) { $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"} else { "(" + $_.DriveLetter + ":)" }}},
                            @{Name="Type"; Expression={"Volume"}},
                            @{Name="LastModifiedDate"; Expression={$null}},
                            @{Name="Size"; Expression={$_.Size}},
                            @{Name="SizeRemaining"; Expression={$_.SizeRemaining}}
    }
    
    <#
    .Synopsis
        Name: Get-Volumes
        Description: Gets the local volumes of the machine.
    
    .Returns
        The local volumes.
    #>
    function Enumerate-Volumes
    {
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace root/Microsoft/Windows/Storage | Where-Object { !$_.IsClustered };
            $partitions = $disks | Get-CimAssociatedInstance -ResultClassName MSFT_Partition;
            if (($partitions -eq $null) -or ($partitions.Length -eq 0)) {
                $volumes = Get-CimInstance -ClassName MSFT_Volume -Namespace root/Microsoft/Windows/Storage;
            } else {
                $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
            }
        }
        else
        {
            $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" };
            $volumes = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
        }
    
        return $volumes | Where-Object { [byte]$_.DriveLetter -ne 0 -and $_.DriveLetter -ne $null -and $_.Size -gt 0 };
    }
    
    Get-FileSystemRoot;
    
}


<#
    
    .SYNOPSIS
        Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.
    
    .DESCRIPTION
        Get settings that apply to the per-profile configurations of the Windows Firewall with Advanced Security.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-FirewallProfile {
    Import-Module netsecurity
    
    Get-NetFirewallProfile -PolicyStore ActiveStore | Microsoft.PowerShell.Utility\Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
}


<#
    
    .SYNOPSIS
        Get Firewall Rules.
    
    .DESCRIPTION
        Get Firewall Rules.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-FirewallRules {
    Import-Module netsecurity
    
    $sidToPrincipalCache = @{};
    
    function getPrincipalForSid($sid) {
    
        if ($sidToPrincipalCache.ContainsKey($sid)) {
        return $sidToPrincipalCache[$sid]
        }
    
        $propertyBag = @{}
        $propertyBag.userName = ""
        $propertyBag.domain = ""
        $propertyBag.principal = ""
        $propertyBag.ssid = $sid
    
        try{
            $win32Sid = [WMI]"root\cimv2:win32_sid.sid='$sid'";
        $propertyBag.userName = $win32Sid.AccountName;
        $propertyBag.domain = $win32Sid.ReferencedDomainName
    
        try {
            $objSID = New-Object System.Security.Principal.SecurityIdentifier($sid)
            try{
            $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
            $propertyBag.principal = $objUser.Value;
            } catch [System.Management.Automation.MethodInvocationException]{
            # the sid couldn't be resolved
            }
    
        } catch [System.Management.Automation.MethodInvocationException]{
            # the sid is invalid
        }
    
        } catch [System.Management.Automation.RuntimeException] {
        # failed to get the user info, which is ok, maybe an old SID
        }
    
        $object = New-Object -TypeName PSObject -Prop $propertyBag
        $sidToPrincipalCache.Add($sid, $object)
    
        return $object
    }
    
    function fillUserPrincipalsFromSddl($sddl, $allowedPrincipals, $skippedPrincipals) {
        if ($sddl -eq $null -or $sddl.count -eq 0) {
        return;
        }
    
        $entries = $sddl.split(@("(", ")"));
        foreach ($entry in $entries) {
        $entryChunks = $entry.split(";");
        $sid = $entryChunks[$entryChunks.count - 1];
        if ($entryChunks[0] -eq "A") {
            $allowed = getPrincipalForSid($sid);
            $allowedPrincipals.Add($allowed) > $null;
        } elseif ($entryChunks[0] -eq "D") {
            $skipped = getPrincipalForSid($sid);
            $skippedPrincipals.Add($skipped) > $null;
        }
        }
    }
    
    $stores = @('PersistentStore','RSOP');
    $allRules = @()
    foreach ($store in $stores){
        $rules = (Get-NetFirewallRule -PolicyStore $store)
    
        $rulesHash = @{}
        $rules | foreach {
        $newRule = ($_ | Microsoft.PowerShell.Utility\Select-Object `
            instanceId, `
            name, `
            displayName, `
            description, `
            displayGroup, `
            group, `
            @{Name="enabled"; Expression={$_.Enabled -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.NetSecurity.Enabled]::True}}, `
            profiles, `
            platform, `
            direction, `
            action, `
            edgeTraversalPolicy, `
            looseSourceMapping, `
            localOnlyMapping, `
            owner, `
            primaryStatus, `
            status, `
            enforcementStatus, `
            policyStoreSource, `
            policyStoreSourceType, `
            @{Name="policyStore"; Expression={$store}}, `
            @{Name="addressFilter"; Expression={""}}, `
            @{Name="applicationFilter"; Expression={""}}, `
            @{Name="interfaceFilter"; Expression={""}}, `
            @{Name="interfaceTypeFilter"; Expression={""}}, `
            @{Name="portFilter"; Expression={""}}, `
            @{Name="securityFilter"; Expression={""}}, `
            @{Name="serviceFilter"; Expression={""}})
    
            $rulesHash[$_.CreationClassName] = $newRule
            $allRules += $newRule  }
    
        $addressFilters = (Get-NetFirewallAddressFilter  -PolicyStore $store)
        $applicationFilters = (Get-NetFirewallApplicationFilter  -PolicyStore $store)
        $interfaceFilters = (Get-NetFirewallInterfaceFilter  -PolicyStore $store)
        $interfaceTypeFilters = (Get-NetFirewallInterfaceTypeFilter  -PolicyStore  $store)
        $portFilters = (Get-NetFirewallPortFilter  -PolicyStore $store)
        $securityFilters = (Get-NetFirewallSecurityFilter  -PolicyStore $store)
        $serviceFilters = (Get-NetFirewallServiceFilter  -PolicyStore $store)
    
        $addressFilters | ForEach-Object {
        $newAddressFilter = $_ | Microsoft.PowerShell.Utility\Select-Object localAddress, remoteAddress;
        $newAddressFilter.localAddress = @($newAddressFilter.localAddress)
        $newAddressFilter.remoteAddress = @($newAddressFilter.remoteAddress)
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.addressFilter = $newAddressFilter
        }
        }
    
        $applicationFilters | ForEach-Object {
        $newApplicationFilter = $_ | Microsoft.PowerShell.Utility\Select-Object program, package;
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.applicationFilter = $newApplicationFilter
        }
        }
    
        $interfaceFilters | ForEach-Object {
        $newInterfaceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceAlias"; Expression={}};
        $newInterfaceFilter.interfaceAlias = @($_.interfaceAlias);
            $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceFilter = $newInterfaceFilter
        }
        }
    
        $interfaceTypeFilters | foreach {
        $newInterfaceTypeFilter  = $_ | Microsoft.PowerShell.Utility\Select-Object @{Name="interfaceType"; Expression={}};
        $newInterfaceTypeFilter.interfaceType = $_.PSbase.CimInstanceProperties["InterfaceType"].Value;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.interfaceTypeFilter = $newInterfaceTypeFilter
        }
        }
    
        $portFilters | foreach {
        $newPortFilter = $_ | Microsoft.PowerShell.Utility\Select-Object dynamicTransport, icmpType, localPort, remotePort, protocol;
        $newPortFilter.localPort = @($newPortFilter.localPort);
        $newPortFilter.remotePort = @($newPortFilter.remotePort);
        $newPortFilter.icmpType = @($newPortFilter.icmpType);
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.portFilter = $newPortFilter
        }
        }
    
        $securityFilters | ForEach-Object {
        $allowedLocalUsers = New-Object System.Collections.ArrayList;
        $skippedLocalUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.localUser -allowedprincipals $allowedLocalUsers -skippedPrincipals $skippedLocalUsers;
    
        $allowedRemoteMachines = New-Object System.Collections.ArrayList;
        $skippedRemoteMachines = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteMachine -allowedprincipals $allowedRemoteMachines -skippedPrincipals $skippedRemoteMachines;
    
        $allowedRemoteUsers = New-Object System.Collections.ArrayList;
        $skippedRemoteUsers = New-Object System.Collections.ArrayList;
        fillUserPrincipalsFromSddl -sddl $_.remoteUser -allowedprincipals $allowedRemoteUsers -skippedPrincipals $skippedRemoteUsers;
    
        $newSecurityFilter = $_ | Microsoft.PowerShell.Utility\Select-Object authentication, `
        encryption, `
        overrideBlockRules, `
        @{Name="allowedLocalUsers"; Expression={}}, `
        @{Name="skippedLocalUsers"; Expression={}}, `
        @{Name="allowedRemoteMachines"; Expression={}}, `
        @{Name="skippedRemoteMachines"; Expression={}}, `
        @{Name="allowedRemoteUsers"; Expression={}}, `
        @{Name="skippedRemoteUsers"; Expression={}};
    
        $newSecurityFilter.allowedLocalUsers = $allowedLocalUsers.ToArray()
        $newSecurityFilter.skippedLocalUsers = $skippedLocalUsers.ToArray()
        $newSecurityFilter.allowedRemoteMachines = $allowedRemoteMachines.ToArray()
        $newSecurityFilter.skippedRemoteMachines = $skippedRemoteMachines.ToArray()
        $newSecurityFilter.allowedRemoteUsers = $allowedRemoteUsers.ToArray()
        $newSecurityFilter.skippedRemoteUsers = $skippedRemoteUsers.ToArray()
    
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.securityFilter = $newSecurityFilter
        }
        }
    
        $serviceFilters | ForEach-Object {
        $newServiceFilter = $_ | Microsoft.PowerShell.Utility\Select-Object serviceName;
        $rule = $rulesHash[$_.CreationClassName];
        if ($rule){
            $rule.serviceFilter = $newServiceFilter
        }
        }
    }
    
    $allRules
    
}


<#
    
    .SYNOPSIS
        Gets the count of elements in the folder
    
    .DESCRIPTION
        Gets the count of elements in the folder
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder
    
#>
function Get-FolderItemCount {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path    
    )
    
    Set-StrictMode -Version 5.0
    
    $directoryInfo = Get-ChildItem $Path | Measure-Object
    $directoryInfo.count
}


<#
    
    .SYNOPSIS
        Gets the owner of a folder.
    
    .DESCRIPTION
        Gets the owner of a folder.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-FolderOwner {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    $Owner = (Get-Acl $Path).Owner
    @{ owner = $Owner; }
}


<#
    
    .SYNOPSIS
        Gets the existing share names of a shared folder
    
    .DESCRIPTION
        Gets the existing share names of a shared folder
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder.
    
#>
function Get-FolderShareNames {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    Get-CimInstance -Class Win32_Share -Filter Path="'$Path'" | Select-Object Name
    
}


<#
    
    .SYNOPSIS
        Gets user access rights to a folder share
    
    .DESCRIPTION
        Gets user access rights to a folder share
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .ROLE
        Administrators

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER Name
        String -- Name of the share.
    
    .PARAMETER AccountName
        String -- The user identification (AD / Local user).
    
    .PARAMETER AccessRight
        String -- Access rights of the user.
    
#>
function Get-FolderShareNameUserAccess {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Name,
    
        [Parameter(Mandatory = $true)]
        [String]
        $AccountName
    )
    
    Set-StrictMode -Version 5.0
    
    Get-SmbShareAccess -Name "$Name" | Select-Object AccountName, AccessControlType, AccessRight | Where-Object {$_.AccountName -eq "$AccountName"}    
}


<#
    
    .SYNOPSIS
        Checks if a folder is shared
    
    .DESCRIPTION
        Checks if a folder is shared
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- the path to the folder.
    
#>
function Get-FolderShareStatus {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    $Shared = [bool](Get-CimInstance -Class Win32_Share -Filter Path="'$Path'")
    @{ isShared = $Shared }
}


<#
    
    .SYNOPSIS
        Gets the user access rights of a folder
    
    .DESCRIPTION
        Gets the user access rights of a folder
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder.
    
#>
function Get-FolderShareUsers {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    Get-Acl $Path | Select-Object -ExpandProperty Access | Select-Object IdentityReference, FileSystemRights
    
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host Enhanced Session Mode settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host Enhnaced Session Mode settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVEnhancedSessionModeSettings {
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        EnableEnhancedSessionMode
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host General settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host General settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVGeneralSettings {
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        VirtualHardDiskPath, `
        VirtualMachinePath
    
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host Physical GPU settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host Physical GPU settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVHostPhysicalGpuSettings {
    Set-StrictMode -Version 5.0
    Import-Module CimCmdlets
    
    Get-CimInstance -Namespace "root\virtualization\v2" -Class "Msvm_Physical3dGraphicsProcessor" | `
        Microsoft.PowerShell.Utility\Select-Object EnabledForVirtualization, `
        Name, `
        DriverDate, `
        DriverInstalled, `
        DriverModelVersion, `
        DriverProvider, `
        DriverVersion, `
        DirectXVersion, `
        PixelShaderVersion, `
        DedicatedVideoMemory, `
        DedicatedSystemMemory, `
        SharedSystemMemory, `
        TotalVideoMemory
    
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host Live Migration settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host Live Migration settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVLiveMigrationSettings {
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        maximumVirtualMachineMigrations, `
        VirtualMachineMigrationAuthenticationType, `
        VirtualMachineMigrationEnabled, `
        VirtualMachineMigrationPerformanceOption
    
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V migration support.
    
    .DESCRIPTION
        Gets a computer's Hyper-V  migration support.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVMigrationSupport {
    Set-StrictMode -Version 5.0
    
    $migrationSettingsDatas=Microsoft.PowerShell.Management\Get-WmiObject -Namespace root\virtualization\v2 -Query "associators of {Msvm_VirtualSystemMigrationCapabilities.InstanceID=""Microsoft:MigrationCapabilities""} where resultclass = Msvm_VirtualSystemMigrationSettingData"
    
    $live = $false;
    $storage = $false;
    
    foreach ($migrationSettingsData in $migrationSettingsDatas) {
        if ($migrationSettingsData.MigrationType -eq 32768) {
            $live = $true;
        }
    
        if ($migrationSettingsData.MigrationType -eq 32769) {
            $storage = $true;
        }
    }
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "liveMigrationSupported" $live;
    $result | Add-Member -MemberType NoteProperty -Name "storageMigrationSupported" $storage;
    $result
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVNumaSpanningSettings {
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        NumaSpanningEnabled
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V role installation state.
    
    .DESCRIPTION
        Gets a computer's Hyper-V role installation state.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVRoleInstalled {
    Set-StrictMode -Version 5.0
     
    $service = Microsoft.PowerShell.Management\get-service -Name "VMMS" -ErrorAction SilentlyContinue;
    
    return ($service -and $service.Name -eq "VMMS");
    
}


<#
    
    .SYNOPSIS
        Gets a computer's Hyper-V Host settings.
    
    .DESCRIPTION
        Gets a computer's Hyper-V Host settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-HyperVStorageMigrationSettings {
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        MaximumStorageMigrations
    
}


<#
    
    .SYNOPSIS
        Get item's properties.
    
    .DESCRIPTION
        Get item's properties on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER Path
        String -- the path to the item whose properites are requested.
    
    .PARAMETER ItemType
        String -- What kind of item?
    
#>
function Get-ItemProperties {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $ItemType
    )
    
    Set-StrictMode -Version 5.0
    
    switch ($ItemType) {
        0 {
            Get-Volume $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
        }
        default {
            Get-ItemProperty $Path | Microsoft.PowerShell.Utility\Select-Object -Property *
        }
    }
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the file system entities (files, folders, volumes) of the system.
    
    .DESCRIPTION
        Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER Path
        String -- the path to the folder where enumeration should start.
    
#>
function Get-ItemType {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    <#
    .Synopsis
        Name: Get-FileSystemEntityType
        Description: Gets the type of a local file system entity.
    
    .Parameter Attributes
        The System.IO.FileAttributes of the FileSystemEntity.
    
    .Returns
        The type of the local file system entity.
    #>
    function Get-FileSystemEntityType
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.IO.FileAttributes]
            $Attributes
        )
    
        if ($Attributes -match "Directory" -or $Attributes -match "ReparsePoint")
        {
            return "Folder";
        }
        else
        {
            return "File";
        }
    }
    
    if (Test-Path -LiteralPath $Path) {
        return Get-FileSystemEntityType -Attributes (Get-Item $Path).Attributes
    } else {
        return ''
    }
    
}


<#
    
    .SYNOPSIS
        Gets the local groups.
    
    .DESCRIPTION
        Gets the local groups. The supported Operating Systems are Window Server 2012,
        Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalGroups {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    Import-Module Microsoft.PowerShell.LocalAccounts -ErrorAction SilentlyContinue
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalGroup -SID $SID | Sort-Object -Property Name | Select-Object Description,
                                                Name,
                                                @{Name="SID"; Expression={$_.SID.Value}},
                                                ObjectClass;
        }
        else
        {
            Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Select-Object Description, Name, SID, ObjectClass;
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalGroup | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Description,
                                    Name,
                                    @{Name="SID"; Expression={$_.SID.Value}},
                                    ObjectClass;
        }
        else
        {
            Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object Description, Name, SID, ObjectClass
        }
    }    
}


<#
    
    .SYNOPSIS
        Get users belong to group.
    
    .DESCRIPTION
        Get users belong to group. The supported Operating Systems are Window Server 2012,
        Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalGroupUsers {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $group
    )
    
    # ADSI does NOT support 2016 Nano, meanwhile Get-LocalGroupMember does NOT support downlevel and also has bug
    $ComputerName = $env:COMPUTERNAME
    try {
        $groupconnection = [ADSI]("WinNT://localhost/$group,group")
        $contents = $groupconnection.Members() | ForEach-Object {
            $path=$_.GetType().InvokeMember("ADsPath", "GetProperty", $NULL, $_, $NULL)
            # $path will looks like:
            #   WinNT://ComputerName/Administrator
            #   WinNT://DomainName/Domain Admins
            # Find out if this is a local or domain object and trim it accordingly
            if ($path -like "*/$ComputerName/*"){
                $start = 'WinNT://' + $ComputerName + '/'
            }
            else {
                $start = 'WinNT://'
            }
            $name = $path.Substring($start.length)
            $name.Replace('/', '\') #return name here
        }
        return $contents
    }
    catch { # if above block failed (say in 2016Nano), use another cmdlet
        # clear existing error info from try block
        $Error.Clear()
        #There is a known issue, in some situation Get-LocalGroupMember return: Failed to compare two elements in the array.
        $contents = Get-LocalGroupMember -group $group
        $names = $contents.Name | ForEach-Object {
            $name = $_
            if ($name -like "$ComputerName\*") {
                $name = $name.Substring($ComputerName.length+1)
            }
            $name
        }
        return $names
    }
    
}


<#
    
    .SYNOPSIS
        Get a local user belong to group list.
    
    .DESCRIPTION
        Get a local user belong to group list. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalUserBelongGroups {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    $operatingSystem = Get-CimInstance Win32_OperatingSystem
    $version = [version]$operatingSystem.Version
    # product type 3 is server, version number ge 10 is server 2016
    $isWinServer2016OrNewer = ($operatingSystem.ProductType -eq 3) -and ($version -ge '10.0')
    
    # ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."
    
    # Step 1: get the list of local groups
    if ($isWinServer2016OrNewer) {
        $grps = net localgroup | Where-Object {$_ -AND $_ -match "^[*]"}  # group member list as "*%Fws\r\n"
        $groups = $grps.trim('*')
    }
    else {
        $grps = Get-WmiObject -Class Win32_Group -Filter "LocalAccount='True'" | Microsoft.PowerShell.Utility\Select-Object Name
        $groups = $grps.Name
    }
    
    # Step 2: in each group, list members and find match to target $UserName
    $groupNames = @()
    $regex = '^' + $UserName + '\b'
    foreach ($group in $groups) {
        $found = $false
        #find group members
        if ($isWinServer2016OrNewer) {
            $members = net localgroup $group | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Microsoft.PowerShell.Utility\Select-Object -skip 4
            if ($members -AND $members.contains($UserName)) {
                $found = $true
            }
        }
        else {
            $groupconnection = [ADSI]("WinNT://localhost/$group,group")
            $members = $groupconnection.Members()
            ForEach ($member in $members) {
                $name = $member.GetType().InvokeMember("Name", "GetProperty", $NULL, $member, $NULL)
                if ($name -AND ($name -match $regex)) {
                    $found = $true
                    break
                }
            }
        }
        #if members contains $UserName, add group name to list
        if ($found) {
            $groupNames = $groupNames + $group
        }
    }
    return $groupNames
    
}


<#
    
    .SYNOPSIS
        Gets the local users.
    
    .DESCRIPTION
        Gets the local users. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalUsers {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser -SID $SID | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                                Description,
                                                Enabled,
                                                FullName,
                                                LastLogon,
                                                Name,
                                                ObjectClass,
                                                PasswordChangeableDate,
                                                PasswordExpires,
                                                PasswordLastSet,
                                                PasswordRequired,
                                                @{Name="SID"; Expression={$_.SID.Value}},
                                                UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                    Description,
                                    Enabled,
                                    FullName,
                                    LastLogon,
                                    Name,
                                    ObjectClass,
                                    PasswordChangeableDate,
                                    PasswordExpires,
                                    PasswordLastSet,
                                    PasswordRequired,
                                    @{Name="SID"; Expression={$_.SID.Value}},
                                    UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }    
}


<#
    
    .SYNOPSIS
        Gets memory summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets memory summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-MemorySummaryDownLevel {
    import-module CimCmdlets
    
    # reset counter reading only first one.
    function Reset($counter) {
        $Global:Utilization = [System.Collections.ArrayList]@()
        for ($i = 0; $i -lt 59; $i++) {
            $Global:Utilization.Insert(0, 0)
        }
    
        $Global:Utilization.Insert(0, $counter)
        $Global:Delta = 0
    }
    
    $memory = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
    $now = get-date
    $system = Get-CimInstance Win32_ComputerSystem
    $percent = 100 * ($system.TotalPhysicalMemory - $memory.AvailableBytes) / $system.TotalPhysicalMemory
    $cached = $memory.StandbyCacheCoreBytes + $memory.StandbyCacheNormalPriorityBytes + $memory.StandbyCacheReserveBytes + $memory.ModifiedPageListBytes
    
    # get sampling time and remember last sample time.
    if (-not $Global:SampleTime) {
        $Global:SampleTime = $now
        $Global:LastTime = $Global:SampleTime
        Reset($percent)
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = $now
        if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            Reset($percent)
        }
        else {
            $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
            while ($Global:Delta -gt 1000) {
                $Global:Delta -= 1000
                $Global:Utilization.Insert(0, $percent)
            }
    
            $Global:Utilization = $Global:Utilization.GetRange(0, 60)
        }
    }
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "Available" $memory.AvailableBytes
    $result | Add-Member -MemberType NoteProperty -Name "Cached" $cached
    $result | Add-Member -MemberType NoteProperty -Name "Total" $system.TotalPhysicalMemory
    $result | Add-Member -MemberType NoteProperty -Name "InUse" ($system.TotalPhysicalMemory - $memory.AvailableBytes)
    $result | Add-Member -MemberType NoteProperty -Name "Committed" $memory.CommittedBytes
    $result | Add-Member -MemberType NoteProperty -Name "PagedPool" $memory.PoolPagedBytes
    $result | Add-Member -MemberType NoteProperty -Name "NonPagedPool" $memory.PoolNonpagedBytes
    $result | Add-Member -MemberType NoteProperty -Name "Utilization" $Global:Utilization
    $result
}


<#
    .SYNOPSIS
        Gets the network ip configuration.
    
    .DESCRIPTION
        Gets the network ip configuration. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-Networks {
    Import-Module NetAdapter
    Import-Module NetTCPIP
    Import-Module DnsClient
    
    Set-StrictMode -Version 5.0
    $ErrorActionPreference = 'SilentlyContinue'
    
    # Get all net information
    $netAdapter = Get-NetAdapter
    
    # conditions used to select the proper ip address for that object modeled after ibiza method.
    # We only want manual (set by user manually), dhcp (set up automatically with dhcp), or link (set from link address)
    # fe80 is the prefix for link local addresses, so that is the format want if the suffix origin is link
    # SkipAsSource -eq zero only grabs ip addresses with skipassource set to false so we only get the preffered ip address
    $ipAddress = Get-NetIPAddress | Where-Object {
        ($_.SuffixOrigin -eq 'Manual') -or
        ($_.SuffixOrigin -eq 'Dhcp') -or 
        (($_.SuffixOrigin -eq 'Link') -and (($_.IPAddress.StartsWith('fe80:')) -or ($_.IPAddress.StartsWith('2001:'))))
    }
    
    $netIPInterface = Get-NetIPInterface
    $netRoute = Get-NetRoute -PolicyStore ActiveStore
    $dnsServer = Get-DnsClientServerAddress
    
    # Load in relevant net information by name
    Foreach ($currentNetAdapter in $netAdapter) {
        $result = New-Object PSObject
    
        # Net Adapter information
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceAlias' -Value $currentNetAdapter.InterfaceAlias
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceIndex' -Value $currentNetAdapter.InterfaceIndex
        $result | Add-Member -MemberType NoteProperty -Name 'InterfaceDescription' -Value $currentNetAdapter.InterfaceDescription
        $result | Add-Member -MemberType NoteProperty -Name 'Status' -Value $currentNetAdapter.Status
        $result | Add-Member -MemberType NoteProperty -Name 'MacAddress' -Value $currentNetAdapter.MacAddress
        $result | Add-Member -MemberType NoteProperty -Name 'LinkSpeed' -Value $currentNetAdapter.LinkSpeed
    
        # Net IP Address information
        # Primary addresses are used for outgoing calls so SkipAsSource is false (0)
        # Should only return one if properly configured, but it is possible to set multiple, so collect all
        $primaryIPv6Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv6Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            $linkLocalArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv6Addresses) {
                if ($address -ne $null -and $address.IPAddress -ne $null -and $address.IPAddress.StartsWith('fe80')) {
                    $linkLocalArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
                else {
                    $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv6Address' -Value $ipArray
            $result | Add-Member -MemberType NoteProperty -Name 'LinkLocalIPv6Address' -Value $linkLocalArray
        }
    
        $primaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 0)}
        if ($primaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $primaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'PrimaryIPv4Address' -Value $ipArray
        }
    
        # Secondary addresses are not used for outgoing calls so SkipAsSource is true (1)
        # There will usually not be secondary addresses, but collect them just in case
        $secondaryIPv6Adresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv6Adresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv6Adresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv6Address' -Value $ipArray
        }
    
        $secondaryIPv4Addresses = $ipAddress | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4') -and ($_.SkipAsSource -eq 1)}
        if ($secondaryIPv4Addresses) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $secondaryIPv4Addresses) {
                $ipArray.Add(($address.IPAddress, $address.PrefixLength)) > $null
            }
            $result | Add-Member -MemberType NoteProperty -Name 'SecondaryIPv4Address' -Value $ipArray
        }
    
        # Net IP Interface information
        $currentDhcpIPv4 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv4')}
        if ($currentDhcpIPv4) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv4' -Value $currentDhcpIPv4.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4Enabled' -Value $false
        }
    
        $currentDhcpIPv6 = $netIPInterface | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 'IPv6')}
        if ($currentDhcpIPv6) {
            $result | Add-Member -MemberType NoteProperty -Name 'DhcpIPv6' -Value $currentDhcpIPv6.Dhcp
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $true
        }
        else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6Enabled' -Value $false
        }
    
        # Net Route information
        # destination prefix for selected ipv6 address is always ::/0
        $currentIPv6DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '::/0')}
        if ($currentIPv6DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DefaultGateway' -Value $ipArray
        }
    
        # destination prefix for selected ipv4 address is always 0.0.0.0/0
        $currentIPv4DefaultGateway = $netRoute | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.DestinationPrefix -eq '0.0.0.0/0')}
        if ($currentIPv4DefaultGateway) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DefaultGateway) {
                if ($address.NextHop) {
                    $ipArray.Add($address.NextHop) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DefaultGateway' -Value $ipArray
        }
    
        # DNS information
        # dns server util code for ipv4 is 2
        $currentIPv4DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 2)}
        if ($currentIPv4DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv4DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DNSServer' -Value $ipArray
        }
    
        # dns server util code for ipv6 is 23
        $currentIPv6DnsServer = $dnsServer | Where-Object {($_.InterfaceAlias -eq $currentNetAdapter.Name) -and ($_.AddressFamily -eq 23)}
        if ($currentIPv6DnsServer) {
            $ipArray = New-Object System.Collections.ArrayList
            Foreach ($address in $currentIPv6DnsServer) {
                if ($address.ServerAddresses) {
                    $ipArray.Add($address.ServerAddresses) > $null
                }
            }
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DNSServer' -Value $ipArray
        }
    
        $adapterGuid = $currentNetAdapter.InterfaceGuid
        if ($adapterGuid) {
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$($adapterGuid)"
          $ipv4Properties = Get-ItemProperty $regPath
          if ($ipv4Properties -and $ipv4Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv4DnsManuallyConfigured' -Value $false
          }
    
          $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces\$($adapterGuid)"
          $ipv6Properties = Get-ItemProperty $regPath
          if ($ipv6Properties -and $ipv6Properties.NameServer) {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $true
          } else {
            $result | Add-Member -MemberType NoteProperty -Name 'IPv6DnsManuallyConfigured' -Value $false
          }
        }
    
        $result
    }
    
}


<#
    
    .SYNOPSIS
        Gets network adapter summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets network adapter summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-NetworkSummaryDownlevel {
    import-module CimCmdlets
    function ResetData($adapterResults) {
        $Global:NetworkResults = @{}
        $Global:PrevAdapterData = @{}
        $Global:Delta = 0
    
        foreach ($key in $adapterResults.Keys) {
            $adapterResult = $adapterResults.Item($key)
            $sentBytes = New-Object System.Collections.ArrayList
            $receivedBytes = New-Object System.Collections.ArrayList
            for ($i = 0; $i -lt 60; $i++) {
                $sentBytes.Insert(0, 0)
                $receivedBytes.Insert(0, 0)
            }
    
            $networkResult = @{
                SentBytes = $sentBytes
                ReceivedBytes = $receivedBytes
            }
            $Global:NetworkResults.Item($key) = $networkResult
        }
    }
    
    function UpdateData($adapterResults) {
        $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
    
        foreach ($key in $adapterResults.Keys) {
            $localDelta = $Global:Delta
    
            # update data for each adapter
            $adapterResult = $adapterResults.Item($key)
            $item = $Global:NetworkResults.Item($key)
            if ($item -ne $null) {
                while ($localDelta -gt 1000) {
                    $localDelta -= 1000
                    $item.SentBytes.Insert(0, $adapterResult.SentBytes)
                    $item.ReceivedBytes.Insert(0, $adapterResult.ReceivedBytes)
                }
    
                $item.SentBytes = $item.SentBytes.GetRange(0, 60)
                $item.ReceivedBytes = $item.ReceivedBytes.GetRange(0, 60)
    
                $Global:NetworkResults.Item($key) = $item
            }
        }
    
        $Global:Delta = $localDelta
    }
    
    $adapters = Get-CimInstance -Namespace root/standardCimV2 MSFT_NetAdapter | Where-Object MediaConnectState -eq 1 | Microsoft.PowerShell.Utility\Select-Object Name, InterfaceIndex, InterfaceDescription
    $activeAddresses = get-CimInstance -Namespace root/standardCimV2 MSFT_NetIPAddress | Microsoft.PowerShell.Utility\Select-Object interfaceIndex
    
    $adapterResults = @{}
    foreach ($adapter in $adapters) {
        foreach ($activeAddress in $activeAddresses) {
            # Find a match between the 2
            if ($adapter.InterfaceIndex -eq $activeAddress.interfaceIndex) {
                $description = $adapter | Microsoft.PowerShell.Utility\Select-Object -ExpandProperty interfaceDescription
    
                if ($Global:UsePerfData -EQ $NULL) {
                    $adapterData = Get-CimInstance -Namespace root/StandardCimv2 MSFT_NetAdapterStatisticsSettingData -Filter "Description='$description'" | Microsoft.PowerShell.Utility\Select-Object ReceivedBytes, SentBytes
    
                    if ($adapterData -EQ $null) {
                        # If above doesnt return data use slower perf data below
                        $Global:UsePerfData = $true
                    }
                }
    
                if ($Global:UsePerfData -EQ $true) {
                    # Need to replace the '#' to ascii since we parse anything after # as a comment
                    $sanitizedDescription = $description -replace [char]35, "_"
                    $adapterData = Get-CimInstance Win32_PerfFormattedData_Tcpip_NetworkAdapter | Where-Object name -EQ $sanitizedDescription | Microsoft.PowerShell.Utility\Select-Object BytesSentPersec, BytesReceivedPersec
    
                    $sentBytes = $adapterData.BytesSentPersec
                    $receivedBytes = $adapterData.BytesReceivedPersec
                }
                else {
                    # set to 0 because we dont have a baseline to subtract from
                    $sentBytes = 0
                    $receivedBytes = 0
    
                    if ($Global:PrevAdapterData -ne $null) {
                        $prevData = $Global:PrevAdapterData.Item($description)
                        if ($prevData -ne $null) {
                            $sentBytes = $adapterData.SentBytes - $prevData.SentBytes
                            $receivedBytes = $adapterData.ReceivedBytes - $prevData.ReceivedBytes
                        }
                    }
                    else {
                        $Global:PrevAdapterData = @{}
                    }
    
                    # Now that we have data, set current data as previous data as baseline
                    $Global:PrevAdapterData.Item($description) = $adapterData
                }
    
                $adapterResult = @{
                    SentBytes = $sentBytes
                    ReceivedBytes = $receivedBytes
                }
                $adapterResults.Item($description) = $adapterResult
                break;
            }
        }
    }
    
    $now = get-date
    
    if (-not $Global:SampleTime) {
        $Global:SampleTime = $now
        $Global:LastTime = $Global:SampleTime
        ResetData($adapterResults)
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = $now
        if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            ResetData($adapterResults)
        }
        else {
            UpdateData($adapterResults)
        }
    }
    
    $Global:NetworkResults
}


<#
    
    .SYNOPSIS
        Gets the number of logged on users.
    
    .DESCRIPTION
        Gets the number of logged on users including active and disconnected users.
        Returns a count of users.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-NumberOfLoggedOnUsers {
    $count = 0
    $error.Clear();
    
    # query user may return an uncatchable error. We need to redirect it.
    # Sends errors (2) and success output (1) to the success output stream.
    $result = query user 2>&1
    
    if ($error.Count -EQ 0)
    {
        # query user does not return a valid ps object and includes the header.
        # subtract 1 to get actual count.
        $count = $result.count -1
    }
    
    @{Count = $count}
}


<#

    .SYNOPSIS
        Gets information about the processes running in downlevel computer.

    .DESCRIPTION
        Gets information about the processes running in downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers

#>
function Get-ProcessDownlevel {
    param
    (
        [Parameter(Mandatory = $true)]
        [boolean]
        $isLocal
    )

    $NativeProcessInfo = @"
namespace SMT
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.InteropServices;

    public class SystemProcess
    {
        public uint processId;
        public uint parentId;
        public string name;
        public string description;
        public string executablePath;
        public string userName;
        public string commandLine;
        public uint sessionId;
        public uint processStatus;
        public ulong cpuTime;
        public ulong cycleTime;
        public DateTime CreationDateTime;
        public ulong workingSetSize;
        public ulong peakWorkingSetSize;
        public ulong privateWorkingSetSize;
        public ulong sharedWorkingSetSize;
        public ulong commitCharge;
        public ulong pagedPool;
        public ulong nonPagedPool;
        public uint pageFaults;
        public uint basePriority;
        public uint handleCount;
        public uint threadCount;
        public uint userObjects;
        public uint gdiObjects;
        public ulong readOperationCount;
        public ulong writeOperationCount;
        public ulong otherOperationCount;
        public ulong readTransferCount;
        public ulong writeTransferCount;
        public ulong otherTransferCount;
        public bool elevated;
        public double cpuPercent;
        public uint operatingSystemContext;
        public uint platform;
        public double cyclePercent;
        public ushort uacVirtualization;
        public ushort dataExecutionPrevention;
        public bool isImmersive;
        public ushort intervalSeconds;
        public ushort deltaWorkingSetSize;
        public ushort deltaPageFaults;
        public bool hasChildWindow;
        public string processType;
        public string fileDescription;

        public SystemProcess(NativeMethods.SYSTEM_PROCESS_INFORMATION processInformation)
        {
            this.processId = (uint)processInformation.UniqueProcessId.ToInt32();
            this.name = Marshal.PtrToStringAuto(processInformation.ImageName.Buffer);
            this.cycleTime = processInformation.CycleTime;
            this.cpuTime = (ulong)(processInformation.KernelTime + processInformation.UserTime);
            this.sessionId = processInformation.SessionId;
            this.workingSetSize = (ulong)(processInformation.WorkingSetSize.ToInt64() / 1024);
            this.peakWorkingSetSize = (ulong)processInformation.PeakWorkingSetSize.ToInt64();
            this.privateWorkingSetSize = (ulong)processInformation.WorkingSetPrivateSize;
            this.sharedWorkingSetSize = (ulong)processInformation.WorkingSetSize.ToInt64() - this.privateWorkingSetSize;
            this.commitCharge = (ulong)processInformation.PrivatePageCount.ToInt64();
            this.pagedPool = (ulong)processInformation.QuotaPagedPoolUsage.ToInt64();
            this.nonPagedPool = (ulong)processInformation.QuotaNonPagedPoolUsage.ToInt64();
            this.pageFaults = processInformation.PageFaultCount;
            this.handleCount = processInformation.HandleCount;
            this.threadCount = processInformation.NumberOfThreads;
            this.readOperationCount = (ulong)processInformation.ReadOperationCount;
            this.writeOperationCount = (ulong)processInformation.WriteOperationCount;
            this.otherOperationCount = (ulong)processInformation.OtherOperationCount;
            this.readTransferCount = (ulong)processInformation.ReadTransferCount;
            this.writeTransferCount = (ulong)processInformation.WriteTransferCount;
            this.otherTransferCount = (ulong)processInformation.OtherTransferCount;
            this.processStatus = 0;

            if(processInformation.BasePriority <= 4)
            {
                this.basePriority = 0x00000040; //IDLE_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 6)
            {
                this.basePriority = 0x00004000; //BELOW_NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 8)
            {
                this.basePriority = 0x00000020; //NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 10)
            {
                this.basePriority = 0x00008000; //ABOVE_NORMAL_PRIORITY_CLASS
            }
            else if (processInformation.BasePriority <= 13)
            {
                this.basePriority = 0x00000080; //HIGH_PRIORITY_CLASS
            }
            else
            {
                this.basePriority = 0x00000100; //REALTIME_PRIORITY_CLASS
            }
        }
    }

    public static class NativeMethods
    {
        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [System.Runtime.InteropServices.StructLayout(LayoutKind.Sequential)]
        public struct SYSTEM_PROCESS_INFORMATION
        {
            internal uint NextEntryOffset;
            internal uint NumberOfThreads;
            internal long WorkingSetPrivateSize;
            internal uint HardFaultCount;
            internal uint NumberOfThreadsHighWatermark;
            internal ulong CycleTime;
            internal long CreateTime;
            internal long UserTime;
            internal long KernelTime;
            internal UNICODE_STRING ImageName;
            internal int BasePriority;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;
            internal uint HandleCount;
            internal uint SessionId;
            internal IntPtr UniqueProcessKey;
            internal IntPtr PeakVirtualSize;
            internal IntPtr VirtualSize;
            internal uint PageFaultCount;
            internal IntPtr PeakWorkingSetSize;
            internal IntPtr WorkingSetSize;
            internal IntPtr QuotaPeakPagedPoolUsage;
            internal IntPtr QuotaPagedPoolUsage;
            internal IntPtr QuotaPeakNonPagedPoolUsage;
            internal IntPtr QuotaNonPagedPoolUsage;
            internal IntPtr PagefileUsage;
            internal IntPtr PeakPagefileUsage;
            internal IntPtr PrivatePageCount;
            internal long ReadOperationCount;
            internal long WriteOperationCount;
            internal long OtherOperationCount;
            internal long ReadTransferCount;
            internal long WriteTransferCount;
            internal long OtherTransferCount;
        }

        public enum TOKEN_INFORMATION_CLASS
        {
            TokenElevation = 20,
            TokenVirtualizationAllowed = 23,
            TokenVirtualizationEnabled = 24
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct TOKEN_ELEVATION
        {
            public Int32 TokenIsElevated;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UAC_ALLOWED
        {
            public Int32 UacAllowed;
        }

        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct UAC_ENABLED
        {
            public Int32 UacEnabled;
        }

        [DllImport("ntdll.dll")]
        internal static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags DesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool InheritHandle, int ProcessId);

        [System.Runtime.InteropServices.DllImport("advapi32", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool OpenProcessToken(IntPtr hProcess, UInt32 desiredAccess, out Microsoft.Win32.SafeHandles.SafeWaitHandle hToken);

        [System.Runtime.InteropServices.DllImport("advapi32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto, SetLastError = true)]
        [return: System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.Bool)]
        public static extern bool GetTokenInformation(SafeWaitHandle hToken, TOKEN_INFORMATION_CLASS tokenInfoClass, IntPtr pTokenInfo, Int32 tokenInfoLength, out Int32 returnLength);

        [System.Runtime.InteropServices.DllImport("user32.dll")]
        public static extern uint GetGuiResources(IntPtr hProcess, uint uiFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        internal const int SystemProcessInformation = 5;

        internal const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);

        internal const uint TOKEN_QUERY = 0x0008;
    }

    public static class Process
    {
        public static IEnumerable<SystemProcess> Enumerate()
        {
            List<SystemProcess> process = new List<SystemProcess>();

            int bufferSize = 1024;

            IntPtr buffer = Marshal.AllocHGlobal(bufferSize);

            QuerySystemProcessInformation(ref buffer, ref bufferSize);

            long totalOffset = 0;

            while (true)
            {
                IntPtr currentPtr = (IntPtr)((long)buffer + totalOffset);

                NativeMethods.SYSTEM_PROCESS_INFORMATION pi = new NativeMethods.SYSTEM_PROCESS_INFORMATION();

                pi = (NativeMethods.SYSTEM_PROCESS_INFORMATION)Marshal.PtrToStructure(currentPtr, typeof(NativeMethods.SYSTEM_PROCESS_INFORMATION));

                process.Add(new SystemProcess(pi));

                if (pi.NextEntryOffset == 0)
                {
                    break;
                }

                totalOffset += pi.NextEntryOffset;
            }

            Marshal.FreeHGlobal(buffer);

            GetExtendedProcessInfo(process);

            return process;
        }

        private static void GetExtendedProcessInfo(List<SystemProcess> processes)
        {
            foreach(var process in processes)
            {
                IntPtr hProcess = GetProcessHandle(process);

                if(hProcess != IntPtr.Zero)
                {
                    try
                    {
                        process.elevated = IsElevated(hProcess);
                        process.userObjects = GetCountUserResources(hProcess);
                        process.gdiObjects = GetCountGdiResources(hProcess);
                        process.uacVirtualization = GetVirtualizationStatus(hProcess);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(hProcess);
                    }
                }
            }
        }

        private static uint GetCountGdiResources(IntPtr hProcess)
        {
            return NativeMethods.GetGuiResources(hProcess, 0);
        }
        private static uint GetCountUserResources(IntPtr hProcess)
        {
            return NativeMethods.GetGuiResources(hProcess, 1);
        }

        private static ushort GetVirtualizationStatus(IntPtr hProcess)
        {
            /* Virtualization status:
             * 0: Unknown
             * 1: Disabled
             * 2: Enabled
             * 3: Not Allowed
             */
            ushort virtualizationStatus = 0;

            try
            {
                if(!IsVirtualizationAllowed(hProcess))
                {
                    virtualizationStatus = 3;
                }
                else
                {
                    if(IsVirtualizationEnabled(hProcess))
                    {
                        virtualizationStatus = 2;
                    }
                    else
                    {
                        virtualizationStatus = 1;
                    }
                }
            }
            catch(Win32Exception)
            {
            }

            return virtualizationStatus;
        }

        private static bool IsVirtualizationAllowed(IntPtr hProcess)
        {
            bool uacVirtualizationAllowed = false;

            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbUacAlowed = 0;
            IntPtr pUacAllowed = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbUacAlowed = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.UAC_ALLOWED));
                pUacAllowed = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbUacAlowed);

                if (pUacAllowed == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenVirtualizationAllowed, pUacAllowed, cbUacAlowed, out cbUacAlowed))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.UAC_ALLOWED uacAllowed = (NativeMethods.UAC_ALLOWED)System.Runtime.InteropServices.Marshal.PtrToStructure(pUacAllowed, typeof(NativeMethods.UAC_ALLOWED));

                uacVirtualizationAllowed = (uacAllowed.UacAllowed != 0);
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pUacAllowed != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pUacAllowed);
                    pUacAllowed = IntPtr.Zero;
                    cbUacAlowed = 0;
                }
            }

            return uacVirtualizationAllowed;
        }

        public static bool IsVirtualizationEnabled(IntPtr hProcess)
        {
            bool uacVirtualizationEnabled = false;

            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbUacEnabled = 0;
            IntPtr pUacEnabled = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbUacEnabled = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.UAC_ENABLED));
                pUacEnabled = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbUacEnabled);

                if (pUacEnabled == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenVirtualizationEnabled, pUacEnabled, cbUacEnabled, out cbUacEnabled))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.UAC_ENABLED uacEnabled = (NativeMethods.UAC_ENABLED)System.Runtime.InteropServices.Marshal.PtrToStructure(pUacEnabled, typeof(NativeMethods.UAC_ENABLED));

                uacVirtualizationEnabled = (uacEnabled.UacEnabled != 0);
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pUacEnabled != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pUacEnabled);
                    pUacEnabled = IntPtr.Zero;
                    cbUacEnabled = 0;
                }
            }

            return uacVirtualizationEnabled;
        }

        private static bool IsElevated(IntPtr hProcess)
        {
             bool fIsElevated = false;
            Microsoft.Win32.SafeHandles.SafeWaitHandle hToken = null;
            int cbTokenElevation = 0;
            IntPtr pTokenElevation = IntPtr.Zero;

            try
            {
                if (!NativeMethods.OpenProcessToken(hProcess, NativeMethods.TOKEN_QUERY, out hToken))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                cbTokenElevation = System.Runtime.InteropServices.Marshal.SizeOf(typeof(NativeMethods.TOKEN_ELEVATION));
                pTokenElevation = System.Runtime.InteropServices.Marshal.AllocHGlobal(cbTokenElevation);

                if (pTokenElevation == IntPtr.Zero)
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                if (!NativeMethods.GetTokenInformation(hToken, NativeMethods.TOKEN_INFORMATION_CLASS.TokenElevation, pTokenElevation, cbTokenElevation, out cbTokenElevation))
                {
                    throw new Win32Exception(System.Runtime.InteropServices.Marshal.GetLastWin32Error());
                }

                NativeMethods.TOKEN_ELEVATION elevation = (NativeMethods.TOKEN_ELEVATION)System.Runtime.InteropServices.Marshal.PtrToStructure(pTokenElevation, typeof(NativeMethods.TOKEN_ELEVATION));

                fIsElevated = (elevation.TokenIsElevated != 0);
            }
            catch (Win32Exception)
            {
            }
            finally
            {
                if (hToken != null)
                {
                    hToken.Close();
                    hToken = null;
                }

                if (pTokenElevation != IntPtr.Zero)
                {
                    System.Runtime.InteropServices.Marshal.FreeHGlobal(pTokenElevation);
                    pTokenElevation = IntPtr.Zero;
                    cbTokenElevation = 0;
                }
            }

            return fIsElevated;
        }

        private static IntPtr GetProcessHandle(SystemProcess process)
        {
            IntPtr hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, (int)process.processId);

            if(hProcess == IntPtr.Zero)
            {
                hProcess = NativeMethods.OpenProcess(NativeMethods.ProcessAccessFlags.QueryLimitedInformation, false, (int)process.processId);
            }

            return hProcess;
        }

        private static void QuerySystemProcessInformation(ref IntPtr processInformationBuffer, ref int processInformationBufferSize)
        {
            const int maxTries = 10;
            bool success = false;

            for (int i = 0; i < maxTries; i++)
            {
                int sizeNeeded;

                int result = NativeMethods.NtQuerySystemInformation(NativeMethods.SystemProcessInformation, processInformationBuffer, processInformationBufferSize, out sizeNeeded);

                if (result == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    if (processInformationBuffer != IntPtr.Zero)
                    {
                        Marshal.FreeHGlobal(processInformationBuffer);
                    }

                    processInformationBuffer = Marshal.AllocHGlobal(sizeNeeded);
                    processInformationBufferSize = sizeNeeded;
                }

                else if (result < 0)
                {
                    throw new Exception(String.Format("NtQuerySystemInformation failed with code 0x{0:X8}", result));
                }

                else
                {
                    success = true;
                    break;
                }
            }

            if (!success)
            {
                throw new Exception("Failed to allocate enough memory for NtQuerySystemInformation");
            }
        }
    }
}
"@

    ############################################################################################################################

    # Global settings for the script.

    ############################################################################################################################

    $ErrorActionPreference = "Stop"

    Set-StrictMode -Version 3.0

    ############################################################################################################################

    # Helper functions.

    ############################################################################################################################

    function Get-ProcessListFromWmi {
        <#
        .Synopsis
            Name: Get-ProcessListFromWmi
            Description: Runs the WMI command to get Win32_Process objects and returns them in hashtable where key is processId.

        .Returns
            The list of processes in the form of hashtable.
        #>
        $processList = @{}

        $WmiProcessList = Get-WmiObject -Class Win32_Process

        foreach ($process in $WmiProcessList) {
            $processList.Add([int]$process.ProcessId, $process)
        }

        $processList
    }

    function Get-ProcessPerfListFromWmi {
        <#
        .Synopsis
            Name: Get-ProcessPerfListFromWmi
            Description: Runs the WMI command to get Win32_PerfFormattedData_PerfProc_Process objects and returns them in hashtable where key is processId.

        .Returns
            The list of processes performance data in the form of hashtable.
        #>
        $processPerfList = @{}

        $WmiProcessPerfList = Get-WmiObject -Class Win32_PerfFormattedData_PerfProc_Process

        foreach ($process in $WmiProcessPerfList) {
            try {
                $processPerfList.Add([int]$process.IdProcess, $process)
            }
            catch {
                if ($_.FullyQualifiedErrorId -eq 'ArgumentException') {
                    $processPerfList.Remove([int]$process.IdProcess)
                }

                $processPerfList.Add([int]$process.IdProcess, $process)
            }
        }

        $processPerfList
    }

    function Get-ProcessListFromPowerShell {
        <#
        .Synopsis
            Name: Get-ProcessListFromPowerShell
            Description: Runs the PowerShell command Get-Process to get process objects.

        .Returns
            The list of processes in the form of hashtable.
        #>
        $processList = @{}

        if ($psVersionTable.psversion.Major -ge 4) {
            #
            # It will crash to run 'Get-Process' with parameter 'IncludeUserName' multiple times in a session.
            # Currently the UI will not reuse the session as a workaround.
            # We need to remove the paramter 'IncludeUserName' if this issue happens again.
            #
            $PowerShellProcessList = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
        }
        else {
            $PowerShellProcessList = Get-Process -ErrorAction SilentlyContinue
        }

        foreach ($process in $PowerShellProcessList) {
            $processList.Add([int]$process.Id, $process)
        }

        $processList
    }

    function Get-LocalSystemAccount {
        <#
        .Synopsis
            Name: Get-LocalSystemAccount
            Description: Gets the name of local system account.

        .Returns
            The name local system account.
        #>
        $sidLocalSystemAccount = "S-1-5-18"

        $objSID = New-Object System.Security.Principal.SecurityIdentifier($sidLocalSystemAccount)

        $objSID.Translate( [System.Security.Principal.NTAccount]).Value
    }

    function Get-NumberOfCores {
        <#
        .Synopsis
            Name: Get-NumberOfCores
            Description: Gets the number of cores on the system.

        .Returns
            The number of cores on the system.
        #>
        $processor = Get-WmiObject -Class Win32_Processor -Property NumberOfCores -ErrorAction Stop
        if ($processor) {
            $cores = $processor.NumberOfCores
            $cores
        }
        else {
            throw 'Unable to get processor information'
        }
    }


    ############################################################################################################################
    # Main script.
    ############################################################################################################################

    Add-Type -TypeDefinition $NativeProcessInfo
    Remove-Variable NativeProcessInfo

    try {
        #
        # Get the information about system processes from different sources.
        #
        $NumberOfCores = Get-NumberOfCores
        $NativeProcesses = [SMT.Process]::Enumerate()
        $WmiProcesses = Get-ProcessListFromWmi
        $WmiPerfProcesses = Get-ProcessPerfListFromWmi
        $PowerShellProcesses = Get-ProcessListFromPowerShell
        $LocalSystemAccount = Get-LocalSystemAccount

        $systemIdleProcess = $null
        $cpuInUse = 0

        # process paths and categorization taken from Task Manager
        # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
        $criticalProcesses = (
            "$($env:windir)\system32\winlogon.exe",
            "$($env:windir)\system32\wininit.exe",
            "$($env:windir)\system32\csrss.exe",
            "$($env:windir)\system32\lsass.exe",
            "$($env:windir)\system32\smss.exe",
            "$($env:windir)\system32\services.exe",
            "$($env:windir)\system32\taskeng.exe",
            "$($env:windir)\system32\taskhost.exe",
            "$($env:windir)\system32\dwm.exe",
            "$($env:windir)\system32\conhost.exe",
            "$($env:windir)\system32\svchost.exe",
            "$($env:windir)\system32\sihost.exe",
            "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:windir)\explorer.exe"
        )

        $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
        $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"

        $edgeProcesses = (
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
            "$($env:windir)\system32\browser_broker.exe"
        )

        #
        # Extract the additional process related information and fill up each nativeProcess object.
        #
        foreach ($nativeProcess in $NativeProcesses) {
            $WmiProcess = $null
            $WmiPerfProcess = $null
            $psProcess = $null

            # Same process as retrieved from WMI call Win32_Process
            if ($WmiProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
                $WmiProcess = $WmiProcesses.Get_Item([int]$nativeProcess.ProcessId)
            }

            # Same process as retrieved from WMI call Win32_PerfFormattedData_PerfProc_Process
            if ($WmiPerfProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
                $WmiPerfProcess = $WmiPerfProcesses.Get_Item([int]$nativeProcess.ProcessId)
            }

            # Same process as retrieved from PowerShell call Win32_Process
            if ($PowerShellProcesses.ContainsKey([int]$nativeProcess.ProcessId)) {
                $psProcess = $PowerShellProcesses.Get_Item([int]$nativeProcess.ProcessId)
            }

            if (($WmiProcess -eq $null) -or ($WmiPerfProcess -eq $null) -or ($psProcess -eq $null)) {continue}

            $nativeProcess.name = $WmiProcess.Name
            $nativeProcess.description = $WmiProcess.Description
            $nativeProcess.executablePath = $WmiProcess.ExecutablePath
            $nativeProcess.commandLine = $WmiProcess.CommandLine
            $nativeProcess.parentId = $WmiProcess.ParentProcessId

            #
            # Process CPU utilization and divide by number of cores
            # Win32_PerfFormattedData_PerfProc_Process PercentProcessorTime has a max number of 100 * cores so we want to normalize it
            #
            $nativeProcess.cpuPercent = $WmiPerfProcess.PercentProcessorTime / $NumberOfCores

            #
            # Process start time.
            #
            if ($WmiProcess.CreationDate) {
                $nativeProcess.CreationDateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime($WmiProcess.CreationDate)
            }
            else {
                if ($nativeProcess.ProcessId -in @(0, 4)) {
                    # Under some circumstances, the process creation time is not available for processs "System Idle Process" or "System"
                    # In this case we assume that the process creation time is when the system was last booted.
                    $nativeProcess.CreationDateTime = [System.Management.ManagementDateTimeConverter]::ToDateTime((Get-WmiObject -Class win32_Operatingsystem).LastBootUpTime)
                }
            }

            #
            # Owner of the process.
            #
            if ($psVersionTable.psversion.Major -ge 4) {
                $nativeProcess.userName = $psProcess.UserName
            }

            # If UserName was not present available in results returned from Get-Process, then get the UserName from WMI class Get-Process
            <#
            ###### GetOwner is too slow so skip this part. ####

            if([string]::IsNullOrWhiteSpace($nativeProcess.userName))
            {
                $processOwner = Invoke-WmiMethod -InputObject $WmiProcess -Name GetOwner -ErrorAction SilentlyContinue

                try
                {
                    if($processOwner.Domain)
                    {
                        $nativeProcess.userName = "{0}\{1}" -f $processOwner.Domain, $processOwner.User
                    }
                    else
                    {
                        $nativeProcess.userName = "{0}" -f $processOwner.User
                    }
                }
                catch
                {
                }

                #In case of 'System Idle Process" and 'System' there is a need to explicitly mention NT Authority\System as Process Owner.
                if([string]::IsNullOrWhiteSpace($nativeProcess.userName) -and $nativeProcess.processId -in @(0, 4))
                {
                    $nativeProcess.userName = Get-LocalSystemAccount
                }
            }
            #>

            #In case of 'System Idle Process" and 'System' there is a need to explicitly mention NT Authority\System as Process Owner.
            if ([string]::IsNullOrWhiteSpace($nativeProcess.userName) -and $nativeProcess.processId -in @(0, 4)) {
                $nativeProcess.userName = $LocalSystemAccount
            }

            #
            # The process status ( i.e. running or suspended )
            #
            $countSuspendedThreads = @($psProcess.Threads | where { $_.WaitReason -eq [System.Diagnostics.ThreadWaitReason]::Suspended }).Count

            if ($psProcess.Threads.Count -eq $countSuspendedThreads) {
                $nativeProcess.ProcessStatus = 2
            }
            else {
                $nativeProcess.ProcessStatus = 1
            }

            # calculate system idle process
            if ($nativeProcess.processId -eq 0) {
                $systemIdleProcess = $nativeProcess
            }
            else {
                $cpuInUse += $nativeProcess.cpuPercent
            }


            if ($isLocal) {
                $nativeProcess.hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0

                if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                    $nativeProcess.fileDescription = $psProcess.MainModule.FileVersionInfo.FileDescription
                }

                if ($edgeProcesses -contains $nativeProcess.executablePath) {
                    # special handling for microsoft edge used by task manager
                    # group all edge processes into applications
                    $nativeProcess.fileDescription = 'Microsoft Edge'
                    $nativeProcess.processType = 'application'
                }
                elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                        -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
                    # process is windows if its executable path is a critical process, defined by Task Manager
                    # if the process has no executable path recorded, fallback to use the name to match to critical process
                    $nativeProcess.processType = 'windows'
                }
                elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
                    # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
                    $nativeProcess.processType = 'application'
                }
                else {
                    $nativeProcess.processType = 'background'
                }
            }
        }

        if ($systemIdleProcess -ne $null) {
            $systemIdleProcess.cpuPercent = [Math]::Max(100 - $cpuInUse, 0)
        }

    }
    catch {
        throw $_
    }
    finally {
        $WmiProcesses = $null
        $WmiPerfProcesses = $null
    }

    # Return the result to the caller of this script.
    $NativeProcesses
}


<#
    
    .SYNOPSIS
        Gets information about the processes running in computer.
    
    .DESCRIPTION
        Gets information about the processes running in computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .COMPONENT
        ProcessList_Body
    
#>
function Get-Processes {
    param
    (
        [Parameter(Mandatory = $true)]
        [boolean]
        $isLocal
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    $processes = Get-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName Msft_MTProcess
    
    $powershellProcessList = @{}
    $powerShellProcesses = Get-Process -ErrorAction SilentlyContinue
    
    foreach ($process in $powerShellProcesses) {
        $powershellProcessList.Add([int]$process.Id, $process)
    }
    
    if ($isLocal) {
        # critical processes taken from task manager code
        # https://microsoft.visualstudio.com/_git/os?path=%2Fbase%2Fdiagnosis%2Fpdui%2Fatm%2FApplications.cpp&version=GBofficial%2Frs_fun_flight&_a=contents&line=44&lineStyle=plain&lineEnd=59&lineStartColumn=1&lineEndColumn=3
        $criticalProcesses = (
            "$($env:windir)\system32\winlogon.exe",
            "$($env:windir)\system32\wininit.exe",
            "$($env:windir)\system32\csrss.exe",
            "$($env:windir)\system32\lsass.exe",
            "$($env:windir)\system32\smss.exe",
            "$($env:windir)\system32\services.exe",
            "$($env:windir)\system32\taskeng.exe",
            "$($env:windir)\system32\taskhost.exe",
            "$($env:windir)\system32\dwm.exe",
            "$($env:windir)\system32\conhost.exe",
            "$($env:windir)\system32\svchost.exe",
            "$($env:windir)\system32\sihost.exe",
            "$($env:ProgramFiles)\Windows Defender\msmpeng.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:ProgramFiles)\Windows Defender\nissrv.exe",
            "$($env:windir)\explorer.exe"
        )
    
        $sidebarPath = "$($end:ProgramFiles)\Windows Sidebar\sidebar.exe"
        $appFrameHostPath = "$($env:windir)\system32\ApplicationFrameHost.exe"
    
        $edgeProcesses = (
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdge.exe",
            "$($env:windir)\SystemApps\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\MicrosoftEdgeCP.exe",
            "$($env:windir)\system32\browser_broker.exe"
        )
    
        foreach ($process in $processes) {
    
            if ($powershellProcessList.ContainsKey([int]$process.ProcessId)) {
                $psProcess = $powershellProcessList.Get_Item([int]$process.ProcessId)
                $hasChildWindow = $psProcess -ne $null -and $psProcess.MainWindowHandle -ne 0
                $process | Add-Member -MemberType NoteProperty -Name "HasChildWindow" -Value $hasChildWindow
                if ($psProcess.MainModule -and $psProcess.MainModule.FileVersionInfo) {
                    $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $psProcess.MainModule.FileVersionInfo.FileDescription
                }
            }
    
            if ($edgeProcesses -contains $nativeProcess.executablePath) {
                # special handling for microsoft edge used by task manager
                # group all edge processes into applications
                $edgeLabel = 'Microsoft Edge'
                if ($process.fileDescription) {
                    $process.fileDescription = $edgeLabel
                }
                else {
                    $process | Add-Member -MemberType NoteProperty -Name "FileDescription" -Value $edgeLabel
                }
    
                $processType = 'application'
            }
            elseif ($criticalProcesses -contains $nativeProcess.executablePath `
                    -or (($nativeProcess.executablePath -eq $null -or $nativeProcess.executablePath -eq '') -and $null -ne ($criticalProcesses | ? {$_ -match $nativeProcess.name})) ) {
                # process is windows if its executable path is a critical process, defined by Task Manager
                # if the process has no executable path recorded, fallback to use the name to match to critical process
                $processType = 'windows'
            }
            elseif (($nativeProcess.hasChildWindow -and $nativeProcess.executablePath -ne $appFrameHostPath) -or $nativeProcess.executablePath -eq $sidebarPath) {
                # sidebar.exe, or has child window (excluding ApplicationFrameHost.exe)
                $processType = 'application'
            }
            else {
                $processType = 'background'
            }
    
            $process | Add-Member -MemberType NoteProperty -Name "ProcessType" -Value $processType
        }
    }
    
    $processes
    
}


<#

    .SYNOPSIS
        Gets the filtered information of all the Operating System handles.

    .DESCRIPTION
        Gets the filtered information of all the Operating System handles.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers

#>
function Get-ProcessHandle {
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'processId')]
        [int]
        $processId,

        [Parameter(Mandatory = $true, ParameterSetName = 'handleSubstring')]
        [string]
        $handleSubstring
    )

    $SystemHandlesInfo = @"
namespace SME
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Globalization;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    public static class NativeMethods
    {
        internal enum SYSTEM_INFORMATION_CLASS : int
        {
            /// </summary>
            SystemHandleInformation = 16
        }

        [Flags]
        internal enum ProcessAccessFlags : int
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SystemHandle
        {
            public Int32 ProcessId;
            public Byte ObjectTypeNumber;
            public Byte Flags;
            public UInt16 Handle;
            public IntPtr Object;
            public Int32 GrantedAccess;
        }

        [Flags]
        public enum DuplicateOptions : int
        {
            NONE = 0,
            /// <summary>
            /// Closes the source handle. This occurs regardless of any error status returned.
            /// </summary>
            DUPLICATE_CLOSE_SOURCE = 0x00000001,
            /// <summary>
            /// Ignores the dwDesiredAccess parameter. The duplicate handle has the same access as the source handle.
            /// </summary>
            DUPLICATE_SAME_ACCESS = 0x00000002
        }

        internal enum OBJECT_INFORMATION_CLASS : int
        {
            /// <summary>
            /// Returns a PUBLIC_OBJECT_BASIC_INFORMATION structure as shown in the following Remarks section.
            /// </summary>
            ObjectBasicInformation = 0,
            ObjectNameInformation = 1,
            /// <summary>
            /// Returns a PUBLIC_OBJECT_TYPE_INFORMATION structure as shown in the following Remarks section.
            /// </summary>
            ObjectTypeInformation = 2
        }

        public enum FileType : int
        {
            FileTypeChar = 0x0002,
            FileTypeDisk = 0x0001,
            FileTypePipe = 0x0003,
            FileTypeRemote = 0x8000,
            FileTypeUnknown = 0x0000,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct GENERIC_MAPPING
        {
            UInt32 GenericRead;
            UInt32 GenericWrite;
            UInt32 GenericExecute;
            UInt32 GenericAll;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct OBJECT_TYPE_INFORMATION
        {
            public UNICODE_STRING TypeName;
            public UInt32 TotalNumberOfObjects;
            public UInt32 TotalNumberOfHandles;
            public UInt32 TotalPagedPoolUsage;
            public UInt32 TotalNonPagedPoolUsage;
            public UInt32 TotalNamePoolUsage;
            public UInt32 TotalHandleTableUsage;
            public UInt32 HighWaterNumberOfObjects;
            public UInt32 HighWaterNumberOfHandles;
            public UInt32 HighWaterPagedPoolUsage;
            public UInt32 HighWaterNonPagedPoolUsage;
            public UInt32 HighWaterNamePoolUsage;
            public UInt32 HighWaterHandleTableUsage;
            public UInt32 InvalidAttributes;
            public GENERIC_MAPPING GenericMapping;
            public UInt32 ValidAccessMask;
            public Boolean SecurityRequired;
            public Boolean MaintainHandleCount;
            public UInt32 PoolType;
            public UInt32 DefaultPagedPoolCharge;
            public UInt32 DefaultNonPagedPoolCharge;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct UNICODE_STRING
        {
            public UInt16 Length;
            public UInt16 MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public String Buffer;
        }

        [DllImport("ntdll.dll")]
        internal static extern Int32 NtQuerySystemInformation(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            IntPtr SystemInformation,
            Int32 SystemInformationLength,
            out Int32 ReturnedLength);

        [DllImport("kernel32.dll")]
        internal static extern IntPtr OpenProcess(
            ProcessAccessFlags dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
            Int32 dwProcessId);

        [DllImport("ntdll.dll")]
        internal static extern UInt32 NtQueryObject(
            Int32 Handle,
            OBJECT_INFORMATION_CLASS ObjectInformationClass,
            IntPtr ObjectInformation,
            Int32 ObjectInformationLength,
            out Int32 ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            UInt32 dwDesiredAccess,
            [MarshalAs(UnmanagedType.Bool)]
            bool bInheritHandle,
            DuplicateOptions dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool QueryFullProcessImageName([In]IntPtr hProcess, [In]Int32 dwFlags, [Out]StringBuilder exeName, ref Int32 size);

        [DllImport("psapi.dll")]
        public static extern UInt32 GetModuleBaseName(IntPtr hProcess, IntPtr hModule, StringBuilder baseName, UInt32 size);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 QueryDosDevice(String lpDeviceName, System.Text.StringBuilder lpTargetPath, Int32 ucchMax);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern FileType GetFileType(IntPtr hFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);

        internal const Int32 STATUS_INFO_LENGTH_MISMATCH = unchecked((Int32)0xC0000004L);
        internal const Int32 STATUS_SUCCESS = 0x00000000;
    }

    public class SystemHandles
    {
        private Queue<SystemHandle> systemHandles;
        private Int32 processId;
        String fileNameToMatch;
        Dictionary<Int32, IntPtr> processIdToHandle;
        Dictionary<Int32, String> processIdToImageName;
        private const Int32 GetObjectNameTimeoutMillis = 50;
        private Thread backgroundWorker;
        private static object syncRoot = new Object();

        public static IEnumerable<SystemHandle> EnumerateAllSystemHandles()
        {
            SystemHandles systemHandles = new SystemHandles();

            return systemHandles.Enumerate(HandlesEnumerationScope.AllSystemHandles);
        }
        public static IEnumerable<SystemHandle> EnumerateProcessSpecificHandles(Int32 processId)
        {
            SystemHandles systemHandles = new SystemHandles(processId);

            return systemHandles.Enumerate(HandlesEnumerationScope.ProcessSpecificHandles);
        }

        public static IEnumerable<SystemHandle> EnumerateMatchingFileNameHandles(String fileNameToMatch)
        {
            SystemHandles systemHandles = new SystemHandles(fileNameToMatch);

            return systemHandles.Enumerate(HandlesEnumerationScope.MatchingFileNameHandles);
        }

        private SystemHandles()
        { }

        public SystemHandles(Int32 processId)
        {
            this.processId = processId;
        }

        public SystemHandles(String fileNameToMatch)
        {
            this.fileNameToMatch = fileNameToMatch;
        }

        public IEnumerable<SystemHandle> Enumerate(HandlesEnumerationScope handlesEnumerationScope)
        {
            IEnumerable<SystemHandle> handles = null;

            this.backgroundWorker = new Thread(() => handles = Enumerate_Internal(handlesEnumerationScope));

            this.backgroundWorker.IsBackground = true;

            this.backgroundWorker.Start();

            return handles;
        }

        public bool IsBusy
        {
            get
            {
                return this.backgroundWorker.IsAlive;
            }
        }

        public bool WaitForEnumerationToComplete(int timeoutMillis)
        {
            return this.backgroundWorker.Join(timeoutMillis);
        }

        private IEnumerable<SystemHandle> Enumerate_Internal(HandlesEnumerationScope handlesEnumerationScope)
        {
            Int32 result;
            Int32 bufferLength = 1024;
            IntPtr buffer = Marshal.AllocHGlobal(bufferLength);
            Int32 requiredLength;
            Int64 handleCount;
            Int32 offset = 0;
            IntPtr currentHandlePtr = IntPtr.Zero;
            NativeMethods.SystemHandle systemHandleStruct;
            Int32 systemHandleStructSize = 0;
            this.systemHandles = new Queue<SystemHandle>();
            this.processIdToHandle = new Dictionary<Int32, IntPtr>();
            this.processIdToImageName = new Dictionary<Int32, String>();

            while (true)
            {
                result = NativeMethods.NtQuerySystemInformation(
                    NativeMethods.SYSTEM_INFORMATION_CLASS.SystemHandleInformation,
                    buffer,
                    bufferLength,
                    out requiredLength);

                if (result == NativeMethods.STATUS_SUCCESS)
                {
                    break;
                }
                else if (result == NativeMethods.STATUS_INFO_LENGTH_MISMATCH)
                {
                    Marshal.FreeHGlobal(buffer);
                    bufferLength *= 2;
                    buffer = Marshal.AllocHGlobal(bufferLength);
                }
                else
                {
                    throw new InvalidOperationException(
                        String.Format(CultureInfo.InvariantCulture, "NtQuerySystemInformation failed with error code {0}", result));
                }
            } // End while loop.

            if (IntPtr.Size == 4)
            {
                handleCount = Marshal.ReadInt32(buffer);
            }
            else
            {
                handleCount = Marshal.ReadInt64(buffer);
            }

            offset = IntPtr.Size;
            systemHandleStruct = new NativeMethods.SystemHandle();
            systemHandleStructSize = Marshal.SizeOf(systemHandleStruct);

            if (handlesEnumerationScope == HandlesEnumerationScope.AllSystemHandles)
            {
                EnumerateAllSystemHandles(buffer, offset, systemHandleStructSize, handleCount);
            }
            else if (handlesEnumerationScope == HandlesEnumerationScope.ProcessSpecificHandles)
            {
                EnumerateProcessSpecificSystemHandles(buffer, offset, systemHandleStructSize, handleCount);
            }
            else if (handlesEnumerationScope == HandlesEnumerationScope.MatchingFileNameHandles)
            {
                this.EnumerateMatchingFileNameHandles(buffer, offset, systemHandleStructSize, handleCount);
            }

            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }

            this.Cleanup();

            return this.systemHandles;
        }

        public IEnumerable<SystemHandle> ExtractResults()
        {
            lock (syncRoot)
            {
                while (this.systemHandles.Count > 0)
                {
                    yield return this.systemHandles.Dequeue();
                }
            }
        }

        private void EnumerateAllSystemHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                ExamineCurrentHandle(currentHandleInfo);

                offset += systemHandleStructSize;
            }
        }

        private void EnumerateProcessSpecificSystemHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                if (currentHandleInfo.ProcessId == this.processId)
                {
                    ExamineCurrentHandle(currentHandleInfo);
                }

                offset += systemHandleStructSize;
            }
        }

        private void EnumerateMatchingFileNameHandles(IntPtr buffer, Int32 offset, Int32 systemHandleStructSize, Int64 handleCount)
        {
            for (Int64 i = 0; i < handleCount; i++)
            {
                NativeMethods.SystemHandle currentHandleInfo =
                        (NativeMethods.SystemHandle)Marshal.PtrToStructure((IntPtr)((Int64)buffer + offset), typeof(NativeMethods.SystemHandle));

                ExamineCurrentHandleForForMatchingFileName(currentHandleInfo, this.fileNameToMatch);

                offset += systemHandleStructSize;
            }
        }

        private void ExamineCurrentHandle(
            NativeMethods.SystemHandle currentHandleInfo)
        {
            IntPtr sourceProcessHandle = this.GetProcessHandle(currentHandleInfo.ProcessId);

            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            String processImageName = this.GetProcessImageName(currentHandleInfo.ProcessId, sourceProcessHandle);

            IntPtr duplicateHandle = CreateDuplicateHandle(sourceProcessHandle, (IntPtr)currentHandleInfo.Handle);

            if (duplicateHandle == IntPtr.Zero)
            {
                return;
            }

            String objectType = GetObjectType(duplicateHandle);

            String objectName = String.Empty;

            if (objectType != "File")
            {
                objectName = GetObjectName(duplicateHandle);
            }
            else
            {
                Thread getObjectNameThread = new Thread(() => objectName = GetObjectName(duplicateHandle));
                getObjectNameThread.IsBackground = true;
                getObjectNameThread.Start();

                if (false == getObjectNameThread.Join(GetObjectNameTimeoutMillis))
                {
                    getObjectNameThread.Abort();

                    getObjectNameThread.Join(GetObjectNameTimeoutMillis);

                    objectName = String.Empty;
                }
                else
                {
                    objectName = GetRegularFileName(objectName);
                }

                getObjectNameThread = null;
            }

            if (!String.IsNullOrWhiteSpace(objectType) &&
                !String.IsNullOrWhiteSpace(objectName))
            {
                SystemHandle systemHandle = new SystemHandle();
                systemHandle.TypeName = objectType;
                systemHandle.Name = objectName;
                systemHandle.ObjectTypeNumber = currentHandleInfo.ObjectTypeNumber;
                systemHandle.ProcessId = currentHandleInfo.ProcessId;
                systemHandle.ProcessImageName = processImageName;

                RegisterHandle(systemHandle);
            }

            NativeMethods.CloseHandle(duplicateHandle);
        }

        private void ExamineCurrentHandleForForMatchingFileName(
             NativeMethods.SystemHandle currentHandleInfo, String fileNameToMatch)
        {
            IntPtr sourceProcessHandle = this.GetProcessHandle(currentHandleInfo.ProcessId);

            if (sourceProcessHandle == IntPtr.Zero)
            {
                return;
            }

            String processImageName = this.GetProcessImageName(currentHandleInfo.ProcessId, sourceProcessHandle);

            if (String.IsNullOrWhiteSpace(processImageName))
            {
                return;
            }

            IntPtr duplicateHandle = CreateDuplicateHandle(sourceProcessHandle, (IntPtr)currentHandleInfo.Handle);

            if (duplicateHandle == IntPtr.Zero)
            {
                return;
            }

            String objectType = GetObjectType(duplicateHandle);

            String objectName = String.Empty;

            Thread getObjectNameThread = new Thread(() => objectName = GetObjectName(duplicateHandle));

            getObjectNameThread.IsBackground = true;

            getObjectNameThread.Start();

            if (false == getObjectNameThread.Join(GetObjectNameTimeoutMillis))
            {
                getObjectNameThread.Abort();

                getObjectNameThread.Join(GetObjectNameTimeoutMillis);

                objectName = String.Empty;
            }
            else
            {
                objectName = GetRegularFileName(objectName);
            }

            getObjectNameThread = null;


            if (!String.IsNullOrWhiteSpace(objectType) &&
                !String.IsNullOrWhiteSpace(objectName))
            {
                if (objectName.ToLower().Contains(fileNameToMatch.ToLower()))
                {
                    SystemHandle systemHandle = new SystemHandle();
                    systemHandle.TypeName = objectType;
                    systemHandle.Name = objectName;
                    systemHandle.ObjectTypeNumber = currentHandleInfo.ObjectTypeNumber;
                    systemHandle.ProcessId = currentHandleInfo.ProcessId;
                    systemHandle.ProcessImageName = processImageName;

                    RegisterHandle(systemHandle);
                }
            }

            NativeMethods.CloseHandle(duplicateHandle);
        }

        private void RegisterHandle(SystemHandle systemHandle)
        {
            lock (syncRoot)
            {
                this.systemHandles.Enqueue(systemHandle);
            }
        }

        private String GetObjectName(IntPtr duplicateHandle)
        {
            String objectName = String.Empty;
            IntPtr objectNameBuffer = IntPtr.Zero;

            try
            {
                Int32 objectNameBufferSize = 0x1000;
                objectNameBuffer = Marshal.AllocHGlobal(objectNameBufferSize);
                Int32 actualObjectNameLength;

                UInt32 queryObjectNameResult = NativeMethods.NtQueryObject(
                    duplicateHandle.ToInt32(),
                    NativeMethods.OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                    objectNameBuffer,
                    objectNameBufferSize,
                    out actualObjectNameLength);

                if (queryObjectNameResult != 0 && actualObjectNameLength > 0)
                {
                    Marshal.FreeHGlobal(objectNameBuffer);
                    objectNameBufferSize = actualObjectNameLength;
                    objectNameBuffer = Marshal.AllocHGlobal(objectNameBufferSize);

                    queryObjectNameResult = NativeMethods.NtQueryObject(
                        duplicateHandle.ToInt32(),
                        NativeMethods.OBJECT_INFORMATION_CLASS.ObjectNameInformation,
                        objectNameBuffer,
                        objectNameBufferSize,
                        out actualObjectNameLength);
                }

                // Get the name
                if (queryObjectNameResult == 0)
                {
                    NativeMethods.UNICODE_STRING name = (NativeMethods.UNICODE_STRING)Marshal.PtrToStructure(objectNameBuffer, typeof(NativeMethods.UNICODE_STRING));

                    objectName = name.Buffer;
                }
            }
            catch (ThreadAbortException)
            {
            }
            finally
            {
                if (objectNameBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(objectNameBuffer);
                }
            }

            return objectName;
        }

        private String GetObjectType(IntPtr duplicateHandle)
        {
            String objectType = String.Empty;

            Int32 objectTypeBufferSize = 0x1000;
            IntPtr objectTypeBuffer = Marshal.AllocHGlobal(objectTypeBufferSize);
            Int32 actualObjectTypeLength;

            UInt32 queryObjectResult = NativeMethods.NtQueryObject(
                duplicateHandle.ToInt32(),
                NativeMethods.OBJECT_INFORMATION_CLASS.ObjectTypeInformation,
                objectTypeBuffer,
                objectTypeBufferSize,
                out actualObjectTypeLength);

            if (queryObjectResult == 0)
            {
                NativeMethods.OBJECT_TYPE_INFORMATION typeInfo = (NativeMethods.OBJECT_TYPE_INFORMATION)Marshal.PtrToStructure(objectTypeBuffer, typeof(NativeMethods.OBJECT_TYPE_INFORMATION));

                objectType = typeInfo.TypeName.Buffer;
            }

            if (objectTypeBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(objectTypeBuffer);
            }

            return objectType;
        }

        private IntPtr GetProcessHandle(Int32 processId)
        {
            if (this.processIdToHandle.ContainsKey(processId))
            {
                return this.processIdToHandle[processId];
            }

            IntPtr processHandle = NativeMethods.OpenProcess
                (NativeMethods.ProcessAccessFlags.DupHandle | NativeMethods.ProcessAccessFlags.QueryInformation | NativeMethods.ProcessAccessFlags.VMRead, false, processId);

            if (processHandle != IntPtr.Zero)
            {
                this.processIdToHandle.Add(processId, processHandle);
            }
            else
            {
                // throw new Win32Exception(Marshal.GetLastWin32Error());
                //  Console.WriteLine("UNABLE TO OPEN PROCESS {0}", processId);
            }

            return processHandle;
        }

        private String GetProcessImageName(Int32 processId, IntPtr handleToProcess)
        {
            if (this.processIdToImageName.ContainsKey(processId))
            {
                return this.processIdToImageName[processId];
            }

            Int32 bufferSize = 1024;

            String strProcessImageName = String.Empty;

            StringBuilder processImageName = new StringBuilder(bufferSize);

            NativeMethods.QueryFullProcessImageName(handleToProcess, 0, processImageName, ref bufferSize);

            strProcessImageName = processImageName.ToString();

            if (!String.IsNullOrWhiteSpace(strProcessImageName))
            {
                try
                {
                    strProcessImageName = Path.GetFileName(strProcessImageName);
                }
                catch
                {
                }

                this.processIdToImageName.Add(processId, strProcessImageName);
            }

            return strProcessImageName;
        }

        private IntPtr CreateDuplicateHandle(IntPtr sourceProcessHandle, IntPtr handleToDuplicate)
        {
            IntPtr currentProcessHandle = Process.GetCurrentProcess().Handle;

            IntPtr duplicateHandle = IntPtr.Zero;

            NativeMethods.DuplicateHandle(
                sourceProcessHandle,
                handleToDuplicate,
                currentProcessHandle,
                out duplicateHandle,
                0,
                false,
                NativeMethods.DuplicateOptions.DUPLICATE_SAME_ACCESS);

            return duplicateHandle;
        }

        private static String GetRegularFileName(String deviceFileName)
        {
            String actualFileName = String.Empty;

            if (!String.IsNullOrWhiteSpace(deviceFileName))
            {
                foreach (var logicalDrive in Environment.GetLogicalDrives())
                {
                    StringBuilder targetPath = new StringBuilder(4096);

                    if (0 == NativeMethods.QueryDosDevice(logicalDrive.Substring(0, 2), targetPath, 4096))
                    {
                        return targetPath.ToString();
                    }

                    String targetPathStr = targetPath.ToString();

                    if (deviceFileName.StartsWith(targetPathStr))
                    {
                        actualFileName = deviceFileName.Replace(targetPathStr, logicalDrive.Substring(0, 2));

                        break;

                    }
                }

                if (String.IsNullOrWhiteSpace(actualFileName))
                {
                    actualFileName = deviceFileName;
                }
            }

            return actualFileName;
        }

        private void Cleanup()
        {
            foreach (var processHandle in this.processIdToHandle.Values)
            {
                NativeMethods.CloseHandle(processHandle);
            }

            this.processIdToHandle.Clear();
        }
    }

    public class SystemHandle
    {
        public String Name { get; set; }
        public String TypeName { get; set; }
        public byte ObjectTypeNumber { get; set; }
        public Int32 ProcessId { get; set; }
        public String ProcessImageName { get; set; }
    }
  
    public enum HandlesEnumerationScope
    {
        AllSystemHandles,
        ProcessSpecificHandles,
        MatchingFileNameHandles
    }
}
"@

    ############################################################################################################################

    # Global settings for the script.

    ############################################################################################################################

    $ErrorActionPreference = "Stop"

    Set-StrictMode -Version 3.0

    ############################################################################################################################

    # Main script.

    ############################################################################################################################


    Add-Type -TypeDefinition $SystemHandlesInfo

    Remove-Variable SystemHandlesInfo

    if ($PSCmdlet.ParameterSetName -eq 'processId' -and $processId -ne $null) {

        $systemHandlesFinder = New-Object -TypeName SME.SystemHandles -ArgumentList $processId

        $scope = [SME.HandlesEnumerationScope]::ProcessSpecificHandles
    }

    elseif ($PSCmdlet.ParameterSetName -eq 'handleSubString') {
        
        $SystemHandlesFinder = New-Object -TypeName SME.SystemHandles -ArgumentList $handleSubstring

        $scope = [SME.HandlesEnumerationScope]::MatchingFileNameHandles
    }


    $SystemHandlesFinder.Enumerate($scope) | out-null

    while($SystemHandlesFinder.IsBusy)
    {
        $SystemHandlesFinder.ExtractResults() | Write-Output
        $SystemHandlesFinder.WaitForEnumerationToComplete(50) | out-null
    }

    $SystemHandlesFinder.ExtractResults() | Write-Output
}


<#
    
    .SYNOPSIS
        Gets services associated with the process.
    
    .DESCRIPTION
        Gets services associated with the process.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ProcessModule {
    param (
        [Parameter(Mandatory=$true)]
        [UInt32]
        $processId
    )
    
    $process = Get-Process -PID $processId
    $process.Modules | Microsoft.PowerShell.Utility\Select-Object ModuleName, FileVersion, FileName, @{Name="Image"; Expression={$process.Name}}, @{Name="PID"; Expression={$process.id}}
    
}


<#
    
    .SYNOPSIS
        Gets processor summary information by performance counter WMI object on downlevel computer.
    
    .DESCRIPTION
        Gets processor summary information by performance counter WMI object on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ProcessorSummaryDownlevel {
    import-module CimCmdlets
    
    # reset counter reading only first one.
    function Reset($counter) {
        $Global:Utilization = [System.Collections.ArrayList]@()
        for ($i = 0; $i -lt 59; $i++) {
            $Global:Utilization.Insert(0, 0)
        }
    
        $Global:Utilization.Insert(0, $counter)
        $Global:Delta = 0
    }
    
    $processorCounter = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "name='_Total'"
    $now = get-date
    $processor = Get-CimInstance Win32_Processor
    $os = Get-CimInstance Win32_OperatingSystem
    $processes = Get-CimInstance Win32_Process
    $percent = $processorCounter.PercentProcessorTime
    $handles = 0
    $threads = 0
    $processes | ForEach-Object { $handles += $_.HandleCount; $threads += $_.ThreadCount }
    $uptime = ($now - $os.LastBootUpTime).TotalMilliseconds * 10000
    
    # get sampling time and remember last sample time.
    if (-not $Global:SampleTime) {
        $Global:SampleTime = $now
        $Global:LastTime = $Global:SampleTime
        Reset($percent)
    }
    else {
        $Global:LastTime = $Global:SampleTime
        $Global:SampleTime = $now
        if ($Global:SampleTime - $Global:LastTime -gt [System.TimeSpan]::FromSeconds(30)) {
            Reset($percent)
        }
        else {
            $Global:Delta += ($Global:SampleTime - $Global:LastTime).TotalMilliseconds
            while ($Global:Delta -gt 1000) {
                $Global:Delta -= 1000
                $Global:Utilization.Insert(0, $percent)
            }
    
            $Global:Utilization = $Global:Utilization.GetRange(0, 60)
        }
    }
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "Name" $processor[0].Name
    $result | Add-Member -MemberType NoteProperty -Name "AverageSpeed" ($processor[0].CurrentClockSpeed / 1000)
    $result | Add-Member -MemberType NoteProperty -Name "Processes" $processes.Length
    $result | Add-Member -MemberType NoteProperty -Name "Uptime" $uptime
    $result | Add-Member -MemberType NoteProperty -Name "Handles" $handles
    $result | Add-Member -MemberType NoteProperty -Name "Threads" $threads
    $result | Add-Member -MemberType NoteProperty -Name "Utilization" $Global:Utilization
    $result
}


<#
    
    .SYNOPSIS
        Gets services associated with the process.
    
    .DESCRIPTION
        Gets services associated with the process.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ProcessService {
    param (
        [Parameter(Mandatory=$true)]
        [Int32]
        $processId
    )
    
    Import-Module CimCmdlets -ErrorAction SilentlyContinue
    
    Get-CimInstance -ClassName Win32_service | Where-Object {$_.ProcessId -eq $processId} | Microsoft.PowerShell.Utility\Select-Object Name, processId, Description, Status, StartName    
}


<#
    
    .SYNOPSIS
        Gets a Microsoft.Sme.PowerShell endpoint configuration.
    
    .DESCRIPTION
        Gets a Microsoft.Sme.PowerShell endpoint configuration.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-RbacSessionConfiguration {
    param(
        [Parameter(Mandatory = $false)]
        [String]
        $configurationName = "Microsoft.Sme.PowerShell"
    )
    
    ## check if it's full administrators
    if ((Get-Command Get-PSSessionConfiguration -ErrorAction SilentlyContinue) -ne $null) {
        @{
            Administrators = $true
            Configured = (Get-PSSessionConfiguration $configurationName -ErrorAction SilentlyContinue) -ne $null
        }
    } else {
        @{
            Administrators = $false
            Configured = $false
        }
    }
}


<#
    
    .SYNOPSIS
        Return subkeys based on the path.
    
    .DESCRIPTION
        Return subkeys based on the path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RegistrySubKeys {
    Param([Parameter(Mandatory = $true)][string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()
    $keyArray = @()
    $key = Get-Item $path
    foreach ($sub in $key.GetSubKeyNames() | Sort-Object)
    {
        $keyEntry = New-Object System.Object
        $keyEntry | Add-Member -type NoteProperty -name Name -value $sub  
        $subKeyPath = $key.PSPath+'\'+$sub
        $keyEntry | Add-Member -type NoteProperty -name Path -value $subKeyPath
        $keyEntry | Add-Member -type NoteProperty -name childCount -value @( Get-ChildItem $subKeyPath -ErrorAction SilentlyContinue ).Length
        $keyArray += $keyEntry
    }
    $keyArray
    
}


<#
    
    .SYNOPSIS
        Return values based on the key path.
    
    .DESCRIPTION
        Return values based on the key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RegistryValues {
    Param([string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()
    $valueArray = @()
    $values = Get-Item  -path $path
    foreach ($val in $values.Property)
      {
        $valueEntry = New-Object System.Object
    
    
        if ($val -eq '(default)'){
            $valueEntry | Add-Member -type NoteProperty -name Name -value $val
            $valueEntry | Add-Member -type NoteProperty -name type -value $values.GetValueKind('')
            $valueEntry | Add-Member -type NoteProperty -name data -value (get-itemproperty -literalpath $path).'(default)'
            }
        else{
            $valueEntry | Add-Member -type NoteProperty -name Name -value $val 
            $valueEntry | Add-Member -type NoteProperty -name type -value $values.GetValueKind($val)
            $valueEntry | Add-Member -type NoteProperty -name data -value $values.GetValue($val)
        }
    
        $valueArray += $valueEntry
      }
      $valueArray    
}


<#
    
    .SYNOPSIS
        Gets a computer's remote desktop settings.
    
    .DESCRIPTION
        Gets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-RemoteDesktop {
    function Get-DenyTSConnectionsValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name fDenyTSConnections -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.fDenyTSConnections
            return $keyValue -ne 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' was not found."
    }
    
    function Get-UserAuthenticationValue {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
        $exists = Get-ItemProperty -Path $key -Name UserAuthentication -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.UserAuthentication
            return $keyValue -eq 1
        }
    
        Write-Error "The value for key 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' was not found."
    }
    
    function Get-RemoteAppSetting {
        $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
        
        $exists = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        if ($exists)
        {
            $keyValue = $exists.EnableRemoteApp
            return $keyValue -eq 1
    
        } else {
            return $false;
        }
    }
    
    $denyValue = Get-DenyTSConnectionsValue;
    $nla = Get-UserAuthenticationValue;
    $remoteApp = Get-RemoteAppSetting;
    
    $result = New-Object -TypeName PSObject
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktop" $denyValue;
    $result | Add-Member -MemberType NoteProperty -Name "allowRemoteDesktopWithNLA" $nla;
    $result | Add-Member -MemberType NoteProperty -Name "enableRemoteApp" $remoteApp;
    $result
}


<#
    
    .SYNOPSIS
        Gets a list of Features / Roles / Role Services on the target server.
    
    .DESCRIPTION
        The data returned for each includes name, description, installstate, installed.
        Can be called with a FeatureName or FeatureType both of which are optional.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .EXAMPLE
        Get-RolesAndFeatures
        When called with no parameters, returns data for all roles, features and role services available on the server
    
    .EXAMPLE
        Get-RolesAndFeatures -FeatureName 'Web-Server'
        When called with a FeatureName (e.g. Web-Server) returns details for the given feature if it is available
    
    .EXAMPLE
        Get-RolesAndFeatures -FeatureType 'Role'
        When called with a FeatureType ('Role', 'Feature' or 'Role Service) returns details for all avilable features
        of that FeatureType
    
    .ROLE
        Readers
    
#>
function Get-RolesAndFeatures {
    param(
        [Parameter(Mandatory=$False)]
        [string]
        $FeatureName = '',
    
        [Parameter(Mandatory=$False)]
        [ValidateSet('Role', 'Role Service', 'Feature', IgnoreCase=$False)]
        [string]
        $FeatureType = ''
    )
    
    Import-Module ServerManager
    
    $result = $null
    
    if ($FeatureName) {
        $result = Get-WindowsFeature -Name $FeatureName
    }
    else {
        if ($FeatureType) {
            $result = Get-WindowsFeature | Where-Object { $_.FeatureType -EQ $FeatureType }
        } else {
            $result = Get-WindowsFeature
        }
    }
    
    $result
    
}


<#
    
    .SYNOPSIS
        Script to get list of scheduled tasks.
    
    .DESCRIPTION
        Script to get list of scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ScheduledTasks {
    param (
      [Parameter(Mandatory = $false)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $false)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    function New-TaskWrapper
    {
      param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        $task
      )
    
      $task | Add-Member -MemberType NoteProperty -Name 'status' -Value $task.state.ToString()
      $info = Get-ScheduledTaskInfo $task
    
      $triggerCopies = @()
      for ($i=0;$i -lt $task.Triggers.Length;$i++)
      {
        $trigger = $task.Triggers[$i];
        $triggerCopy = $trigger.PSObject.Copy();
        if ($trigger -ne $null) {
            if ($trigger.StartBoundary -eq $null -or$trigger.StartBoundary -eq '') 
            {
                $startDate = $null;
            }
            else 
            {
                $startDate = [datetime]($trigger.StartBoundary)
            }
          
            $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerAtDate' -Value $startDate -TypeName System.DateTime
    
            if ($trigger.EndBoundary -eq $null -or$trigger.EndBoundary -eq '') 
            {
                $endDate = $null;
            }
            else 
            {
                $endDate = [datetime]($trigger.EndBoundary)
            }
            
            $triggerCopy | Add-Member -MemberType NoteProperty -Name 'TriggerEndDate' -Value $endDate -TypeName System.DateTime
    
            $triggerCopies += $triggerCopy
        }
    
      }
    
      $task | Add-Member -MemberType NoteProperty -Name 'TriggersEx' -Value $triggerCopies
    
      New-Object -TypeName PSObject -Property @{
          
          ScheduledTask = $task
          ScheduledTaskInfo = $info
      }
    }
    
    if ($taskPath -and $taskName) {
      try
      {
        $task = Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName -ErrorAction Stop
        New-TaskWrapper $task
      }
      catch
      {
      }
    } else {
        Get-ScheduledTask | ForEach-Object {
          New-TaskWrapper $_
        }
    }
    
}


<#
    
    .SYNOPSIS
        Gets status of the connection to the server.
    
    .DESCRIPTION
        Gets status of the connection to the server.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ServerConnectionStatus {
    import-module CimCmdlets
    
    $OperatingSystem = Get-CimInstance Win32_OperatingSystem
    $Caption = $OperatingSystem.Caption
    $ProductType = $OperatingSystem.ProductType
    $Version = $OperatingSystem.Version
    $Status = @{ Label = $null; Type = 0; Details = $null; }
    $Result = @{ Status = $Status; Caption = $Caption; ProductType = $ProductType; Version = $Version; }
    if ($Version -and ($ProductType -eq 2 -or $ProductType -eq 3)) {
        $V = [version]$Version
        $V2016 = [version]'10.0'
        $V2012 = [version]'6.2'
        $V2008r2 = [version]'6.1'
        
        if ($V -ge $V2016) {
            return $Result;
        } 
        
        if ($V -ge $V2008r2) {
            $Key = 'HKLM:\\SOFTWARE\\Microsoft\\PowerShell\\3\\PowerShellEngine'
            $WmfStatus = $false;
            $Exists = Get-ItemProperty -Path $Key -Name PowerShellVersion -ErrorAction SilentlyContinue
            if ($Exists -and ($Exists.Length -ne 0)) {
                $WmfVersionInstalled = $exists.PowerShellVersion
                if ($WmfVersionInstalled.StartsWith('5.')) {
                    $WmfStatus = $true;
                }
            }
    
            if (!$WmfStatus) {            
                $status.Label = 'wmfMissing-label'
                $status.Type = 3
                $status.Details = 'wmfMissing-details'
            }
    
            return $result;
        }
    }
    
    $status.Label = 'unsupported-label'
    $status.Type = 3
    $status.Details = 'unsupported-details'
    return $result;
    
}


<#
    .SYNOPSIS
        Retrieves the inventory data for a server.
    
    .DESCRIPTION
        Retrieves the inventory data for a server.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ServerInventory {
    Set-StrictMode -Version 5.0
    
    import-module CimCmdlets
    
    <#
        .SYNOPSIS
        Converts an arbitrary version string into just 'Major.Minor'
        
        .DESCRIPTION
        To make OS version comparisons we only want to compare the major and 
        minor version.  Build number and/os CSD are not interesting.
    #>
    function convertOsVersion([string] $osVersion) {
        try {
            $version = New-Object Version $osVersion -ErrorAction Stop
    
            if ($version -and $version.Major -ne -1 -and $version.Minor -ne -1) {
                $versionString = "{0}.{1}" -f $version.Major, $version.Minor
    
                return New-Object Version $versionString
            }
        }
        catch {
            # The version string is not in the correct format
            return $null
        }
    }
    
    <#
        .SYNOPSIS
        Determines if CredSSP is enabled for the current server or client.
        
        .DESCRIPTION
        Check the registry value for the CredSSP enabled state.
    #>
    function isCredSSPEnabled() {
        $CredSsp = Get-Item WSMan:\localhost\Service\Auth\CredSSP -ErrorAction SilentlyContinue
        if ($CredSSp) {
            return [System.Convert]::ToBoolean($CredSsp.Value)
        }
    
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V role is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V role is installed when the VMMS service is available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVRoleInstalled() {
        $vmmsService = Get-Service -Name "VMMS" -ErrorAction SilentlyContinue
    
        return $vmmsService -and $vmmsService.Name -eq "VMMS"
    }
    
    <#
        .SYNOPSIS
        Determines if the Hyper-V PowerShell support module is installed for the current server or client.
        
        .DESCRIPTION
        The Hyper-V PowerShell support module is installed when the modules cmdlets are available.  This is much
        faster then checking Get-WindowsFeature and works on Windows Client SKUs.
    #>
    function isHyperVPowerShellSupportInstalled() {
        # quicker way to find the module existence. it doesn't load the module.
        return !!(Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)
    }
    
    <#
        .SYNOPSIS
        Determines if Windows Management Framework (WMF) 5.0, or higher, is installed for the current server or client.
        
        .DESCRIPTION
        Windows Admin Center requires WMF 5 so check the registey for WMF version on Windows versions that are less than
        Windows Server 2016.
    #>
    function isWMF5Installed([string] $operatingSystemVersion) {
        Set-Variable Server2016 -Option Constant -Value (New-Object Version '10.0')   # And Windows 10 client SKUs
        Set-Variable Server2012 -Option Constant -Value (New-Object Version '6.2')
    
        $version = convertOsVersion $operatingSystemVersion
        if ($version -eq $null) {
            return $false        # Since the OS version string is not properly formatted we cannot know the true installed state.
        }
        
        if ($version -ge $Server2016) {
            # It's okay to assume that 2016 and up comes with WMF 5 or higher installed
            return $true
        } else {
            if ($version -ge $Server2012) {
                # Windows 2012/2012R2 are supported as long as WMF 5 or higher is installed
                $registryKey = 'HKLM:\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine'
                $registryKeyValue = Get-ItemProperty -Path $registryKey -Name PowerShellVersion -ErrorAction SilentlyContinue
        
                if ($registryKeyValue -and ($registryKeyValue.PowerShellVersion.Length -ne 0)) {
                    $installedWmfVersion = [Version]$registryKeyValue.PowerShellVersion
        
                    if ($installedWmfVersion -ge [Version]'5.0') {
                        return $true
                    }
                }
            }
        }
        
        return $false
    }
    
    <#
        .SYNOPSIS
        Determines if the current usser is a system administrator of the current server or client.
        
        .DESCRIPTION
        Determines if the current usser is a system administrator of the current server or client.
    #>
    function isUserAnAdministrator() {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    }
    
    <#
        .SYNOPSIS
        Determines if the current server supports Failover Clusters Time Series Database.
        
        .DESCRIPTION
        Use the existance of the cluster cmdlet Get-ClusterPerformanceHistory to determine if TSDB 
        is supported or not.
    #>
    function getClusterPerformanceHistoryCmdLet($failoverClusters) {
        return $failoverClusters.ExportedCommands.ContainsKey("Get-ClusterPerformanceHistory")
    }
    
    <#
        .SYNOPSIS
        Get some basic information about the Failover Cluster that is running on this server.
        
        .DESCRIPTION
        Create a basic inventory of the Failover Cluster that may be running in this server.
    #>
    function getClusterInformation() {
        # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
        Import-Module FailoverClusters -ErrorAction SilentlyContinue
    
        $returnValues = @{}
    
        $returnValues.IsTsdbEnabled = $false
        $returnValues.IsCluster = $false
        $returnValues.ClusterFqdn = $null
    
        $failoverClusters = Get-Module FailoverClusters -ErrorAction SilentlyContinue
        if ($failoverClusters) {
            $returnValues.IsTsdbEnabled = getClusterPerformanceHistoryCmdLet $failoverClusters
        }
    
        $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
        if ($namespace) {
            $cluster = Get-CimInstance -Namespace root/MSCluster -Query "Select fqdn from MSCluster_Cluster" -ErrorAction SilentlyContinue
            if ($cluster) {
                $returnValues.IsCluster = $true
                $returnValues.ClusterFqdn = $cluster.fqdn
            }
        }
        
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the passed in computer name.
    #>
    function getComputerFqdn($computerName) {
        return ([System.Net.Dns]::GetHostEntry($computerName)).HostName
    }
    
    <#
        .SYNOPSIS
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
        
        .DESCRIPTION
        Get the Fully Qaulified Domain (DNS domain) Name (FQDN) of the current server or client.
    #>
    function getHostFqdn($computerSystem) {
        $computerName = $computerSystem.DNSHostName
        if ($computerName -eq $null) {
            $computerName = $computerSystem.Name
        }
    
        return getComputerFqdn $computerName
    }
    
    <#
        .SYNOPSIS
        Are the needed management CIM interfaces available on the current server or client.
        
        .DESCRIPTION
        Check for the presence of the required server management CIM interfaces.
    #>
    function getManagementToolsSupportInformation() {
        $returnValues = @{}
    
        $returnValues.ManagementToolsAvailable = $false
        $returnValues.ServerManagerAvailable = $false
    
        $namespaces = Get-CimInstance -Namespace root/microsoft/windows -ClassName __NAMESPACE -ErrorAction SilentlyContinue
    
        if ($namespaces) {
            $returnValues.ManagementToolsAvailable = ($namespaces | Where-Object { $_.Name -ieq "ManagementTools" }) -ne $null
            $returnValues.ServerManagerAvailable = ($namespaces | Where-Object { $_.Name -ieq "ServerManager" }) -ne $null
        }
    
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    function isRemoteAppEnabled() {
        Set-Variable key -Option Constant -Value "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server"
        Set-Variable enableRemoteAppPropertyName -Option Constant -Value "EnableRemoteApp"
    
        $registryKeyValue = Get-ItemProperty -Path $key -Name EnableRemoteApp -ErrorAction SilentlyContinue
        
        return $registryKeyValue -and ($registryKeyValue.PSObject.Properties.Name -match $enableRemoteAppPropertyName)
    }
    
    <#
        .SYNOPSIS
        Check the remote app enabled or not.
        
        .DESCRIPTION
        Check the remote app enabled or not.
    #>
    
    <#
        .SYNOPSIS
        Get the Win32_OperatingSystem information
        
        .DESCRIPTION
        Get the Win32_OperatingSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getOperatingSystemInfo() {
        return Get-CimInstance Win32_OperatingSystem | Microsoft.PowerShell.Utility\Select-Object csName, Caption, OperatingSystemSKU, Version, ProductType
    }
    
    <#
        .SYNOPSIS
        Get the Win32_ComputerSystem information
        
        .DESCRIPTION
        Get the Win32_ComputerSystem instance and filter the results to just the required properties.
        This filtering will make the response payload much smaller.
    #>
    function getComputerSystemInfo() {
        return Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | `
            Microsoft.PowerShell.Utility\Select-Object TotalPhysicalMemory, DomainRole, Manufacturer, Model, NumberOfLogicalProcessors, Domain, Workgroup, DNSHostName, Name, PartOfDomain
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    $operatingSystem = getOperatingSystemInfo
    $computerSystem = getComputerSystemInfo
    $isAdministrator = isUserAnAdministrator
    $fqdn = getHostFqdn $computerSystem
    $managementToolsInformation = getManagementToolsSupportInformation
    $isWmfInstalled = isWMF5Installed $operatingSystem.Version
    $clusterInformation = getClusterInformation -ErrorAction SilentlyContinue
    $isHyperVPowershellInstalled = isHyperVPowerShellSupportInstalled
    $isHyperVRoleInstalled = isHyperVRoleInstalled
    $isCredSSPEnabled = isCredSSPEnabled
    $isRemoteAppEnabled = isRemoteAppEnabled
    
    $result = New-Object PSObject
    
    $result | Add-Member -MemberType NoteProperty -Name 'IsAdministrator' -Value $isAdministrator
    $result | Add-Member -MemberType NoteProperty -Name 'OperatingSystem' -Value $operatingSystem
    $result | Add-Member -MemberType NoteProperty -Name 'ComputerSystem' -Value $computerSystem
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $fqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsManagementToolsAvailable' -Value $managementToolsInformation.ManagementToolsAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsServerManagerAvailable' -Value $managementToolsInformation.ServerManagerAvailable
    $result | Add-Member -MemberType NoteProperty -Name 'IsCluster' -Value $clusterInformation.IsCluster
    $result | Add-Member -MemberType NoteProperty -Name 'ClusterFqdn' -Value $clusterInformation.ClusterFqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsWmfInstalled' -Value $isWmfInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsTsdbEnabled' -Value $clusterInformation.IsTsdbEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVRoleInstalled' -Value $isHyperVRoleInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsHyperVPowershellInstalled' -Value $isHyperVPowershellInstalled
    $result | Add-Member -MemberType NoteProperty -Name 'IsCredSSPEnabled' -Value $isCredSSPEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'isRemoteAppEnabled' -Value $isRemoteAppEnabled
    
    $result
    
}


<#
    
    .SYNOPSIS
        Gets the path for the specified service.
    
    .DESCRIPTION
        Gets the path for the specified service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ServiceImagePath {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName
    )
    
    $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
    $properties = Get-ItemProperty $regPath -Name ImagePath
    if ($properties -and $properties.ImagePath) {
        $properties.ImagePath
    }
}


<#

    .SYNOPSIS
        Get all services information details using native APIs where Windows Server Manager WMI provider is not available.

    .DESCRIPTION
        Get all services information details using native APIs where Windows Server Manager WMI provider is not available.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers

#>
function Get-ServiceList {
    $NativeServiceInfo = @"
namespace SMT
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security.Permissions;

    public static class Service
    {
        private enum ErrorCode
        {
            ERROR_INSUFFICIENT_BUFFER = 122
        }

        private enum ACCESS_MASK
        {
            STANDARD_RIGHTS_REQUIRED = 0x000F0000
        }

        private enum ServiceInfoLevel
        {
            SC_ENUM_PROCESS_INFO = 0
        }

        private enum ConfigInfoLevel
        {
            SERVICE_CONFIG_DESCRIPTION = 0x01,
            SERVICE_CONFIG_FAILURE_ACTIONS = 0x02,
            SERVICE_CONFIG_DELAYED_AUTO_START_INFO = 0x03,
            SERVICE_CONFIG_TRIGGER_INFO = 0x08
        }

        private enum ServiceType
        {
            SERVICE_KERNEL_DRIVER = 0x1,
            SERVICE_FILE_SYSTEM_DRIVER = 0x2,
            SERVICE_WIN32_OWN_PROCESS = 0x10,
            SERVICE_WIN32_SHARE_PROCESS = 0x20,
            SERVICE_INTERACTIVE_PROCESS = 0x100,
            SERVICE_WIN32 = (SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS)
        }

        private enum ServiceStateRequest
        {
            SERVICE_ACTIVE = 0x1,
            SERVICE_INACTIVE = 0x2,
            SERVICE_STATE_ALL = (SERVICE_ACTIVE | SERVICE_INACTIVE)
        }

        private enum ServiceControlManagerType
        {
            SC_MANAGER_CONNECT = 0x1,
            SC_MANAGER_CREATE_SERVICE = 0x2,
            SC_MANAGER_ENUMERATE_SERVICE = 0x4,
            SC_MANAGER_LOCK = 0x8,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x10,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x20,
            SC_MANAGER_ALL_ACCESS = ACCESS_MASK.STANDARD_RIGHTS_REQUIRED | SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE | SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_LOCK | SC_MANAGER_QUERY_LOCK_STATUS | SC_MANAGER_MODIFY_BOOT_CONFIG
        }

        private enum ServiceAcessRight
        {
            SERVICE_QUERY_CONFIG = 0x00000001
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SERVICE_DESCRIPTION
        {
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public String lpDescription;
        }

        [StructLayout(LayoutKind.Sequential)]
        public class SERVICE_DELAYED_AUTO_START_INFO
        {
            public bool fDelayedAutostart;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class SERVICE_TRIGGER_INFO
        {
            public UInt32 cTriggers;
            public IntPtr pTriggers;
            public IntPtr pReserved;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public class QUERY_SERVICE_CONFIG
        {
            public UInt32 dwServiceType;
            public UInt32 dwStartType;
            public UInt32 dwErrorControl;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpBinaryPathName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpLoadOrderGroup;
            public UInt32 dwTagId;
            public IntPtr lpDependencies;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpServiceStartName;
            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            public string lpDisplayName;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 4)]
        internal struct ENUM_SERVICE_STATUS_PROCESS
        {
            internal static readonly int SizePack4 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS));

            /// <summary>
            /// sizeof(ENUM_SERVICE_STATUS_PROCESS) allow Packing of 8 on 64 bit machines
            /// </summary>
            internal static readonly int SizePack8 = Marshal.SizeOf(typeof(ENUM_SERVICE_STATUS_PROCESS)) + 4;

            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            internal string pServiceName;

            [MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
            internal string pDisplayName;

            internal SERVICE_STATUS_PROCESS ServiceStatus;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SERVICE_STATUS_PROCESS
        {
            public UInt32 serviceType;
            public UInt32 currentState;
            public UInt32 controlsAccepted;
            public UInt32 win32ExitCode;
            public UInt32 serviceSpecificExitCode;
            public UInt32 checkPoint;
            public UInt32 waitHint;
            public UInt32 processId;
            public UInt32 serviceFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct ServiceDetail
        {
            public string Name;
            public string DisplayName;
            public string Description;
            public UInt32 StartupType;
            public bool IsDelayedAutoStart;
            public bool IsTriggered;
            public UInt32 SupportedControlCodes;
            public UInt32 Status;
            public UInt64 ExitCode;
            public string[] DependentServices;
        }

        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenService(IntPtr hSCManager, String lpServiceName, UInt32 dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool EnumServicesStatusEx(IntPtr hSCManager,
            int infoLevel, int dwServiceType,
            int dwServiceState, IntPtr lpServices, UInt32 cbBufSize,
            out uint pcbBytesNeeded, out uint lpServicesReturned,
            ref uint lpResumeHandle, string pszGroupName);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfigW")]
        public static extern Boolean QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "QueryServiceConfig2W")]
        public static extern Boolean QueryServiceConfig2(IntPtr hService, UInt32 dwInfoLevel, IntPtr buffer, UInt32 cbBufSize, out UInt32 pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseServiceHandle(IntPtr hSCObject);

        //  
        // This is an arbitrary number, the apis we call doesn't specify a maximum and could ask for more  
        // buffer space. The function will actually handles scenarios where this buffer  
        // is not big enough. This is just to enable an optimization that we don't call the system api's  
        // twice. 
        // According to QueryServiceConfig and QueryServiceConfig2 functions MSDN doc, the maximum size of the buffer is 8K bytes. 
        //  
        const UInt32 defaultPageSizeInBytes = 4096;

        static void Main(string[] args)
        {
            GetServiceDetail();
        }

        public static ServiceDetail[] GetServiceDetail()
        {
            List<ServiceDetail> results = new List<ServiceDetail>();
            UInt32 uiBytesNeeded;
            bool success;
            UInt32 currentConfigBufferSizeInBytes = defaultPageSizeInBytes;
            IntPtr pSrvConfigBuffer;

            //  
            // Open the service control manager with query and enumerate rights, required for getting the  
            // configuration information and enumerating the services & their dependent services  
            // 
            IntPtr databaseHandle = OpenSCManager(null, null,
                (uint)ServiceControlManagerType.SC_MANAGER_CONNECT | (uint)ServiceControlManagerType.SC_MANAGER_ENUMERATE_SERVICE);
            if (databaseHandle == IntPtr.Zero)
                throw new System.Runtime.InteropServices.ExternalException("Error OpenSCManager\n");

            ENUM_SERVICE_STATUS_PROCESS[] services = GetServicesStatus(databaseHandle);
            // Pre allocate buffer
            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
            try
            {
                foreach (ENUM_SERVICE_STATUS_PROCESS service in services)
                {
                    string serviceName = service.pServiceName;
                    IntPtr serviceHandle = OpenService(databaseHandle, serviceName, (uint)ServiceAcessRight.SERVICE_QUERY_CONFIG);
                    if (serviceHandle == IntPtr.Zero)
                        throw new System.Runtime.InteropServices.ExternalException("Error OpenService name:" + serviceName);
                    ServiceDetail item = new ServiceDetail();
                    item.Name = serviceName;
                    item.DisplayName = service.pDisplayName;
                    item.Status = service.ServiceStatus.currentState;
                    item.SupportedControlCodes = service.ServiceStatus.controlsAccepted;

                    //  
                    // Get the description of the service, if fail record just move on  
                    //  
                    success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DESCRIPTION, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        //Directly using Marshal.PtrToStringAuto(pSrvConfigBuffer) won't work here, have to use structure
                        SERVICE_DESCRIPTION descriptionStruct = new SERVICE_DESCRIPTION();
                        Marshal.PtrToStructure(pSrvConfigBuffer, descriptionStruct);
                        item.Description = descriptionStruct.lpDescription;
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig2 for SERVICE_CONFIG_DESCRIPTION of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    // Get the delayed auto start info, if fail just record and move on
                    success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_DELAYED_AUTO_START_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        SERVICE_DELAYED_AUTO_START_INFO delayedStruct = new SERVICE_DELAYED_AUTO_START_INFO();
                        Marshal.PtrToStructure(pSrvConfigBuffer, delayedStruct);
                        item.IsDelayedAutoStart = delayedStruct.fDelayedAutostart;
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig2 for SERVICE_CONFIG_DELAYED_AUTO_START_INFO of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    // SERVICE_CONFIG_TRIGGER_INFO is only support Windows 7 and above, if fail just move on 
                    success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_TRIGGER_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig2(serviceHandle, (uint)ConfigInfoLevel.SERVICE_CONFIG_TRIGGER_INFO, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        SERVICE_TRIGGER_INFO triggerStruct = new SERVICE_TRIGGER_INFO();
                        Marshal.PtrToStructure(pSrvConfigBuffer, triggerStruct);
                        item.IsTriggered = triggerStruct.cTriggers > 0;
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig2 for SERVICE_CONFIG_TRIGGER_INFO of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    //  
                    // Get the service startup type and dependent services list, if fail just move on  
                    //
                    success = QueryServiceConfig(serviceHandle, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                    if (!success)
                    {
                        int dwError = Marshal.GetLastWin32Error();
                        if (dwError == (int)ErrorCode.ERROR_INSUFFICIENT_BUFFER)
                        {
                            //release old buffer and assign new one in the size of n times of defaultPageSizeInBytes,
                            //  then call the api again
                            Marshal.FreeHGlobal(pSrvConfigBuffer);
                            currentConfigBufferSizeInBytes = (uint)Math.Ceiling((double)uiBytesNeeded / (double)defaultPageSizeInBytes) * defaultPageSizeInBytes;
                            pSrvConfigBuffer = Marshal.AllocHGlobal((int)currentConfigBufferSizeInBytes);
                            success = QueryServiceConfig(serviceHandle, pSrvConfigBuffer, currentConfigBufferSizeInBytes, out uiBytesNeeded);
                        }
                    }

                    if (success)
                    {
                        QUERY_SERVICE_CONFIG configStruct = new QUERY_SERVICE_CONFIG();
                        Marshal.PtrToStructure(pSrvConfigBuffer, configStruct);
                        item.StartupType = configStruct.dwStartType;

                        List<string> dependents = new List<string>();
                        unsafe
                        {
                            // convert IntPtr to wchar_t(2 bytes) pointer
                            ushort* pCurrentDependent = (ushort*)configStruct.lpDependencies.ToPointer();
                            while (pCurrentDependent != null && *pCurrentDependent != '\0')
                            {
                                string sd = Marshal.PtrToStringAuto((IntPtr)pCurrentDependent);
                                dependents.Add(sd);
                                pCurrentDependent += sd.Length + 1;
                            }

                        }
                        item.DependentServices = dependents.ToArray();
                    }
                    else
                    {
                        Console.Error.WriteLine(string.Format("QueryServiceConfig of service {0}, error code:{1}",
                            item.Name, Marshal.GetLastWin32Error()));
                    }

                    CloseServiceHandle(serviceHandle);
                    results.Add(item);
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pSrvConfigBuffer);
                CloseServiceHandle(databaseHandle);
            }

            return results.ToArray();
        }

        [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
        internal static ENUM_SERVICE_STATUS_PROCESS[] GetServicesStatus(IntPtr databaseHandle)
        {
            if (databaseHandle == IntPtr.Zero)
            {
                return null;
            }

            List<ENUM_SERVICE_STATUS_PROCESS> result = new List<ENUM_SERVICE_STATUS_PROCESS>();

            IntPtr buffer = IntPtr.Zero;
            uint uiBytesNeeded = 0;
            uint ServicesReturnedCount = 0;
            uint uiResumeHandle = 0;

            try
            {
                //The maximum size of this array is 256K bytes. Determine the required size first
                EnumServicesStatusEx(databaseHandle, (int)ServiceInfoLevel.SC_ENUM_PROCESS_INFO, (int)ServiceType.SERVICE_WIN32,
                    (int)ServiceStateRequest.SERVICE_STATE_ALL, IntPtr.Zero, 0, out uiBytesNeeded, out ServicesReturnedCount, ref uiResumeHandle, null);
                // allocate memory to receive the data for all services
                buffer = Marshal.AllocHGlobal((int)uiBytesNeeded);

                if (!EnumServicesStatusEx(databaseHandle, (int)ServiceInfoLevel.SC_ENUM_PROCESS_INFO, (int)ServiceType.SERVICE_WIN32,
                    (int)ServiceStateRequest.SERVICE_STATE_ALL, buffer, uiBytesNeeded, out uiBytesNeeded, out ServicesReturnedCount, ref uiResumeHandle, null))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                ENUM_SERVICE_STATUS_PROCESS serviceStatus;

                // 64 bit system has extra pack sizes
                if (IntPtr.Size == 8)
                {
                    long pointer = buffer.ToInt64();
                    for (int i = 0; i < (int)ServicesReturnedCount; i++)
                    {
                        serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(new IntPtr(pointer),
                         typeof(ENUM_SERVICE_STATUS_PROCESS));
                        result.Add(serviceStatus);

                        // incremement pointer to next struct
                        pointer += ENUM_SERVICE_STATUS_PROCESS.SizePack8;
                    }
                }
                else //32 bit
                {
                    int pointer = buffer.ToInt32();
                    for (int i = 0; i < (int)ServicesReturnedCount; i++)
                    {
                        serviceStatus = (ENUM_SERVICE_STATUS_PROCESS)Marshal.PtrToStructure(new IntPtr(pointer),
                         typeof(ENUM_SERVICE_STATUS_PROCESS));
                        result.Add(serviceStatus);

                        // incremement pointer to next struct
                        pointer += ENUM_SERVICE_STATUS_PROCESS.SizePack4;
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return result.ToArray();
        }
    }
}
"@

    $cp = New-Object System.CodeDom.Compiler.CompilerParameters
    $cp.ReferencedAssemblies.AddRange(('System.dll', 'System.ComponentModel.dll', 'System.Runtime.InteropServices.dll'))
    $cp.CompilerOptions = '/unsafe'

    Add-Type -TypeDefinition $NativeServiceInfo -CompilerParameters $cp
    Remove-Variable NativeServiceInfo

    $NativeServices = [SMT.Service]::GetServiceDetail()
    return $NativeServices
}


<#
    
    .SYNOPSIS
        Gets the current log on user for the specified service
    
    .DESCRIPTION
        Gets the current log on user for the specified service

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ServiceLogOnUser {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName
    )
    
    $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
    $properties = Get-ItemProperty $regPath -Name ObjectName
    if ($properties -and $properties.ObjectName) {
        $properties.ObjectName
    }
    else {
        "LocalSystem"
    }    
}


<#
    
    .SYNOPSIS
        Gets the recovery options for a specific service.
    
    .DESCRIPTION
        Gets the recovery options for a specific service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-ServiceRecoveryOptions {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName
    )
    
    function Get-FailureAction {
        param (
            [Parameter(Mandatory = $true)] [int] $failureCode
        )
    
        $failureAction = switch ($failureCode) {
            0 { 'none' }
            1 { 'restart' }
            2 { 'reboot' }
            3 { 'run' }
            default {'none'}
        }
    
        $failureAction
    }
    
    
    $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
    $properties = Get-ItemProperty $regPath
    
    if ($properties -and $properties.FailureActions) {
        # value we get from the registry is a list of bytes that make up a list of little endian dword
        # each byte is in an integer representation from 0-255
    
        # convert each byte from an integer into hex, padding single digits to the left (ex: 191 -> BF, 2 -> 02)
        $properties.FailureActions = $properties.FailureActions | Foreach { [convert]::toString($_, 16).PadLeft(2, "0")}
    
        $dwords = New-Object System.Collections.ArrayList
        # break up list of bytes into dwords
        for ($i = 3; $i -lt $properties.FailureActions.length; $i += 4) {
            # make a dword that is a list of 4 bytes
            $dword = $properties.FailureActions[($i - 3)..$i]
            # reverse bytes in the dword to convert to big endian
            [array]::Reverse($dword)
            # concat list of bytes into one hex string then convert to a decimal
            $dwords.Add([convert]::toint32([string]::Concat($dword), 16)) > $null
        }
    
        # whole blob is type SERVICE_FAILURE_ACTIONS https://msdn.microsoft.com/en-ca/library/windows/desktop/ms685939(v=vs.85).aspx
        # resetPeriod is dwords 0 in seconds
        # dwords 5-6 is first action type SC_ACTION https://msdn.microsoft.com/en-ca/library/windows/desktop/ms685126(v=vs.85).aspx
        # dwords 7-8 is second
        # dwords 9-10 is last
    
        #convert dwords[0] from seconds to days
        $dwordslen = $dwords.Count
        if ($dwordslen -ge 0) {
            $resetFailCountIntervalDays = $dwords[0] / (60 * 60 * 24)
        }
    
        if ($dwordslen -ge 7) {
            $firstFailure = Get-FailureAction $dwords[5]
            if ($firstFailure -eq 'restart') {
                $restartIntervalMinutes = $dwords[6] / (1000 * 60)
            }
        }
    
        if ($dwordslen -ge 9) {
            $secondFailure = Get-FailureAction $dwords[7]
            if ($secondFailure -eq 'restart') {
                $restartIntervalMinutes = $dwords[8] / (1000 * 60)
            }
        }
    
        if ($dwordslen -ge 11) {
            $thirdFailure = Get-FailureAction $dwords[9]
            if ($thirdFailure -eq 'restart') {
                $restartIntervalMinutes = $dwords[10] / (1000 * 60)
            }
        }
    }
    
    # programs stored as "C:/Path/To Program" {command line params}
    if ($properties.FailureCommand) {
        # split up the properties but keep quoted command as one word
        $splitCommand = $properties.FailureCommand -Split ' +(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)'
        if ($splitCommand) {
            $splitLen = $splitCommand.Length
            if ($splitLen -gt 0) {
                # trim quotes from program path for display purposes
                $pathToProgram = $splitCommand[0].Replace("`"", "")
            }
    
            if ($splitLen -gt 1) {
                $parameters = $splitCommand[1..($splitLen - 1)] -Join ' '
            }
        }
    }
    
    $result = New-Object PSObject
    $result | Add-Member -MemberType NoteProperty -Name 'ResetFailCountInterval' -Value $resetFailCountIntervalDays
    $result | Add-Member -MemberType NoteProperty -Name 'RestartServiceInterval' -Value $restartIntervalMinutes
    $result | Add-Member -MemberType NoteProperty -Name 'FirstFailure' -Value $firstFailure
    $result | Add-Member -MemberType NoteProperty -Name 'SecondFailure' -Value $secondFailure
    $result | Add-Member -MemberType NoteProperty -Name 'ThirdFailure' -Value $thirdFailure
    $result | Add-Member -MemberType NoteProperty -Name 'PathToProgram' -Value $pathToProgram
    $result | Add-Member -MemberType NoteProperty -Name 'ProgramParameters' -Value $parameters
    $result
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the local disks of the system.
    
    .DESCRIPTION
        Enumerates all of the local disks of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-StorageDisk {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $DiskId
    )
    
    Import-Module CimCmdlets
    Import-Module Microsoft.PowerShell.Utility
    
    <#
    .Synopsis
        Name: Get-Disks
        Description: Gets all the local disks of the machine.
    
    .Parameters
        $DiskId: The unique identifier of the disk desired (Optional - for cases where only one disk is desired).
    
    .Returns
        The local disk(s).
    #>
    function Get-DisksInternal
    {
        param (
            [Parameter(Mandatory = $false)]
            [String]
            $DiskId
        )
    
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace Root\Microsoft\Windows\Storage | Where-Object { !$_.IsClustered };
        }
        else
        {
            $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace Root\Microsoft\Windows\Storage| Where-Object { $_.FriendlyName -like "Win*" };
            $disks = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Disk;
        }
    
        if ($DiskId)
        {
            $disks = $disks | Where-Object { $_.UniqueId -eq $DiskId };
        }
    
    
        $disks | %{
        $partitions = $_ | Get-CimAssociatedInstance -ResultClassName MSFT_Partition
        $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume
        $volumeIds = @()
        $volumes | %{
            
            $volumeIds += $_.path 
        }
            
        $_ | Add-Member -NotePropertyName VolumeIds -NotePropertyValue $volumeIds
    
        }
    
        $disks = $disks | ForEach-Object {
    
           $disk = @{
                AllocatedSize = $_.AllocatedSize;
                BootFromDisk = $_.BootFromDisk;
                BusType = $_.BusType;
                FirmwareVersion = $_.FirmwareVersion;
                FriendlyName = $_.FriendlyName;
                HealthStatus = $_.HealthStatus;
                IsBoot = $_.IsBoot;
                IsClustered = $_.IsClustered;
                IsOffline = $_.IsOffline;
                IsReadOnly = $_.IsReadOnly;
                IsSystem = $_.IsSystem;
                LargestFreeExtent = $_.LargestFreeExtent;
                Location = $_.Location;
                LogicalSectorSize = $_.LogicalSectorSize;
                Model = $_.Model;
                NumberOfPartitions = $_.NumberOfPartitions;
                OfflineReason = $_.OfflineReason;
                OperationalStatus = $_.OperationalStatus;
                PartitionStyle = $_.PartitionStyle;
                Path = $_.Path;
                PhysicalSectorSize = $_.PhysicalSectorSize;
                ProvisioningType = $_.ProvisioningType;
                SerialNumber = $_.SerialNumber;
                Signature = $_.Signature;
                Size = $_.Size;
                UniqueId = $_.UniqueId;
                UniqueIdFormat = $_.UniqueIdFormat;
                volumeIds = $_.volumeIds;
                Number = $_.Number;
            }
            if (-not $isDownLevel)
            {
                $disk.IsHighlyAvailable = $_.IsHighlyAvailable;
                $disk.IsScaleOut = $_.IsScaleOut;
            }
            return $disk;
        }
    
        if ($isDownlevel)
        {
            $healthStatusMap = @{
                0 = 3;
                1 = 0;
                4 = 1;
                8 = 2;
            };
    
            $operationalStatusMap = @{
                0 = @(0);      # Unknown
                1 = @(53264);  # Online
                2 = @(53265);  # Not ready
                3 = @(53266);  # No media
                4 = @(53267);  # Offline
                5 = @(53268);  # Error
                6 = @(13);     # Lost communication
            };
    
            $disks = $disks | ForEach-Object {
                $_.HealthStatus = $healthStatusMap[[int32]$_.HealthStatus];
                $_.OperationalStatus = $operationalStatusMap[[int32]$_.OperationalStatus[0]];
                $_;
            };
        }
    
        return $disks;
    }
    
    if ($DiskId)
    {
        Get-DisksInternal -DiskId $DiskId
    }
    else
    {
        Get-DisksInternal
    }
    
}


<#
    
    .SYNOPSIS
        Enumerates all of the local file shares of the system.
    
    .DESCRIPTION
        Enumerates all of the local file shares of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER FileShareId
        The file share ID.

#>
function Get-StorageFileShare {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $FileShareId
    )
    
    Import-Module CimCmdlets
    
    <#
    .Synopsis
        Name: Get-FileShares-Internal
        Description: Gets all the local file shares of the machine.
    
    .Parameters
        $FileShareId: The unique identifier of the file share desired (Optional - for cases where only one file share is desired).
    
    .Returns
        The local file share(s).
    #>
    function Get-FileSharesInternal
    {
        param (
            [Parameter(Mandatory = $false)]
            [String]
            $FileShareId
        )
    
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            # Map downlevel status to array of [health status, operational status, share state] uplevel equivalent
            $statusMap = @{
                "OK" =         @(0, 2, 1);
                "Error" =      @(2, 6, 2);
                "Degraded" =   @(1, 3, 2);
                "Unknown" =    @(5, 0, 0);
                "Pred Fail" =  @(1, 5, 2);
                "Starting" =   @(1, 8, 0);
                "Stopping" =   @(1, 9, 0);
                "Service" =    @(1, 11, 1);
                "Stressed" =   @(1, 4, 1);
                "NonRecover" = @(2, 7, 2);
                "No Contact" = @(2, 12, 2);
                "Lost Comm" =  @(2, 13, 2);
            };
            
            $shares = Get-CimInstance -ClassName Win32_Share |
                ForEach-Object {
                    return @{
                        ContinuouslyAvailable = $false;
                        Description = $_.Description;
                        EncryptData = $false;
                        FileSharingProtocol = 3;
                        HealthStatus = $statusMap[$_.Status][0];
                        IsHidden = $_.Name.EndsWith("`$");
                        Name = $_.Name;
                        OperationalStatus = ,@($statusMap[$_.Status][1]);
                        ShareState = $statusMap[$_.Status][2];
                        UniqueId = "smb|" + (Get-CimInstance Win32_ComputerSystem).DNSHostName + "." + (Get-CimInstance Win32_ComputerSystem).Domain + "\" + $_.Name;
                        VolumePath = $_.Path;
                    }
                }
        }
        else
        {        
            $shares = Get-CimInstance -ClassName MSFT_FileShare -Namespace Root\Microsoft\Windows/Storage |
                ForEach-Object {
                    return @{
                        IsHidden = $_.Name.EndsWith("`$");
                        VolumePath = $_.VolumeRelativePath;
                        ContinuouslyAvailable = $_.ContinuouslyAvailable;
                        Description = $_.Description;
                        EncryptData = $_.EncryptData;
                        FileSharingProtocol = $_.FileSharingProtocol;
                        HealthStatus = $_.HealthStatus;
                        Name = $_.Name;
                        OperationalStatus = $_.OperationalStatus;
                        UniqueId = $_.UniqueId;
                        ShareState = $_.ShareState;
                    }
                }
        }
    
        if ($FileShareId)
        {
            $shares = $shares | Where-Object { $_.UniqueId -eq $FileShareId };
        }
    
        return $shares;
    }
    
    if ($FileShareId)
    {
        Get-FileSharesInternal -FileShareId $FileShareId;
    }
    else
    {
        Get-FileSharesInternal;
    }
    
}


<#
    
    .SYNOPSIS
        Get all Quotas.
    
    .DESCRIPTION
        Get all Quotas.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#> 
function Get-StorageQuota {
    Import-Module FileServerResourceManager
    Get-FsrmQuota
}


<#
    
    .SYNOPSIS
        Get disk and volume space details required for resizing volume.
    
    .DESCRIPTION
        Get disk and volume space details required for resizing volume.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER driveLetter
        The drive letter
    
#> 
function Get-StorageResizeDetails {
     param (
            [Parameter(Mandatory = $true)]
            [String]
            $driveLetter
        )
    Import-Module Storage
    
    # Get volume details
    $volume = get-Volume -DriveLetter $driveLetter
    
    $volumeTotalSize = $volume.Size
    
    # Get partition details by drive letter
    $partition = get-Partition -DriveLetter $driveLetter
    
    $partitionNumber =$partition.PartitionNumber
    $diskNumber = $partition.DiskNumber
    
    $disk = Get-Disk -Number $diskNumber
    
    $totalSize = $disk.Size
    
    $allocatedSize = $disk.AllocatedSize
    
    # get unallocated space on the disk
    $unAllocatedSize = $totalSize - $allocatedSize
    
    $sizes = Get-PartitionSupportedSize -DiskNumber $diskNumber -PartitionNumber $partitionNumber
    
    $resizeDetails=@{
      "volumeTotalSize" = $volumeTotalSize;
      "unallocatedSpaceSize" = $unAllocatedSize;
      "minSize" = $sizes.sizeMin;
      "maxSize" = $sizes.sizeMax;
     }
    
     return $resizeDetails
}


<#
    
    .SYNOPSIS
        Enumerates all of the local volumes of the system.
    
    .DESCRIPTION
        Enumerates all of the local volumes of the system.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER VolumeId
        The volume ID
    
#>
function Get-StorageVolume {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $VolumeId
    )
    
    ############################################################################################################################
    
    # Global settings for the script.
    
    ############################################################################################################################
    
    $ErrorActionPreference = "Stop"
    
    Set-StrictMode -Version 3.0
    
    Import-Module CimCmdlets
    Import-Module Microsoft.PowerShell.Management
    Import-Module Microsoft.PowerShell.Utility
    Import-Module Storage
    
    ############################################################################################################################
    
    # Helper functions.
    
    ############################################################################################################################
    
    <# 
    .Synopsis
        Name: Get-VolumePathToPartition
        Description: Gets the list of partitions (that have volumes) in hashtable where key is volume path.
    
    .Returns
        The list of partitions (that have volumes) in hashtable where key is volume path.
    #>
    function Get-VolumePathToPartition
    {
        $volumePaths = @{}
    
        foreach($partition in Get-Partition)
        {
            foreach($volumePath in @($partition.AccessPaths))
            {
                if($volumePath -and (-not $volumePaths.Contains($volumePath)))
                {
                    $volumePaths.Add($volumePath, $partition)
                }
            }
        }
        
        $volumePaths
    }
    
    <# 
    .Synopsis
        Name: Get-DiskIdToDisk
        Description: Gets the list of all the disks in hashtable where key is:
                     "Disk.Path" in case of WS2016 and above.
                     OR
                     "Disk.ObjectId" in case of WS2012 and WS2012R2.
    
    .Returns
        The list of partitions (that have volumes) in hashtable where key is volume path.
    #>
    function Get-DiskIdToDisk
    {    
        $diskIds = @{}
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    
        # In downlevel Operating systems. MSFT_Partition.DiskId is equal to MSFT_Disk.ObjectId
        # However, In WS2016 and above,   MSFT_Partition.DiskId is equal to MSFT_Disk.Path
    
        foreach($disk in Get-Disk)
        {
            if($isDownlevel)
            {
                $diskId = $disk.ObjectId
            }
            else
            {
                $diskId = $disk.Path
            }
    
            if(-not $diskIds.Contains($diskId))
            {
                $diskIds.Add($diskId, $disk)
            }
        }
    
        return $diskIds
    }
    
    <# 
    .Synopsis
        Name: Get-VolumeWs2016AndAboveOS
        Description: Gets the list of all applicable volumes from WS2012 and Ws2012R2 Operating Systems.
                     
    .Returns
        The list of all applicable volumes
    #>
    function Get-VolumeDownlevelOS
    {
        $volumes = @()
        
        foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
        {
           $partition = $script:partitions.Get_Item($volume.Path)
    
           # Check if this volume is associated with a partition.
           if($partition)
           {
                # If this volume is associated with a partition, then get the disk to which this partition belongs.
                $disk = $script:disks.Get_Item($partition.DiskId)
    
                # If the disk is a clustered disk then simply ignore this volume.
                if($disk -and $disk.IsClustered) {continue}
           }
      
           $volumes += $volume
        }
    
        $volumes
    }
    
    <# 
    .Synopsis
        Name: Get-VolumeWs2016AndAboveOS
        Description: Gets the list of all applicable volumes from WS2016 and above Operating System.
                     
    .Returns
        The list of all applicable volumes
    #>
    function Get-VolumeWs2016AndAboveOS
    {
        $volumes = @()
        
        $applicableVolumePaths = @{}
    
        $subSystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" }
    
        foreach($volume in @($subSystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume))
        {
            if(-not $applicableVolumePaths.Contains($volume.Path))
            {
                $applicableVolumePaths.Add($volume.Path, $null)
            }
        }
    
        foreach($volume in (Get-WmiObject -Class MSFT_Volume -Namespace root/Microsoft/Windows/Storage))
        {
            if(-not $applicableVolumePaths.Contains($volume.Path)) { continue }
    
            $volumes += $volume
        }
    
        $volumes
    }
    
    <# 
    .Synopsis
        Name: Get-VolumesList
        Description: Gets the list of all applicable volumes w.r.t to the target Operating System.
                     
    .Returns
        The list of all applicable volumes.
    #>
    function Get-VolumesList
    {
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    
        if($isDownlevel)
        {
             return Get-VolumeDownlevelOS
        }
    
        Get-VolumeWs2016AndAboveOS
    }
    
    ############################################################################################################################
    
    # Helper Variables
    
    ############################################################################################################################
    
    $script:fixedDriveType = 3
    
    $script:disks = Get-DiskIdToDisk
    
    $script:partitions = Get-VolumePathToPartition
    
    ############################################################################################################################
    
    # Main script.
    
    ############################################################################################################################
    
    $resultantVolumes = @()
    
    $volumes = Get-VolumesList
    
    foreach($volume in $volumes)
    {
        $partition = $script:partitions.Get_Item($volume.Path)
    
        if($partition -and $volume.DriveType -eq $script:fixedDriveType)
        {
            $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $partition.IsSystem
            $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $partition.IsBoot
            $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $partition.IsActive
            $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue $partition.PartitionNumber
            $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue $partition.DiskNumber
    
        }
        else
        {
            # This volume is not associated with partition, as such it is representing devices like CD-ROM, Floppy drive etc.
            $volume | Add-Member -NotePropertyName IsSystem -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName IsBoot -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName IsActive -NotePropertyValue $true
            $volume | Add-Member -NotePropertyName PartitionNumber -NotePropertyValue -1
            $volume | Add-Member -NotePropertyName DiskNumber -NotePropertyValue -1
        }
           
        $resultantVolumes += $volume
    }
    
    $resultantVolumes | % {
        [String] $name = '';
     
        # On the downlevel OS, the drive letter is showing charachter. The ASCII code for that char is 0.
        # So rather than checking null or empty, code is checking the ASCII code of the drive letter and updating 
        # the drive letter field to null explicitly to avoid discrepencies on UI.
        if ($_.FileSystemLabel -and [byte]$_.DriveLetter -ne 0 ) 
        { 
             $name = $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"
        } 
        elseif (!$_.FileSystemLabel -and [byte]$_.DriveLetter -ne 0 ) 
        { 
              $name =  "(" + $_.DriveLetter + ":)" 
        }
        elseif ($_.FileSystemLabel -and [byte]$_.DriveLetter -eq 0)
        {
             $name = $_.FileSystemLabel
        }
        else 
        {
             $name = ''
        }
    
        if ([byte]$_.DriveLetter -eq 0)
        {
            $_.DriveLetter = $null
        }
    
        $_ | Add-Member -Force -NotePropertyName "Name" -NotePropertyValue $name
          
    }
    
    $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
    $resultantVolumes = $resultantVolumes | ForEach-Object {
    
    $volume = @{
            Name = $_.Name;
            DriveLetter = $_.DriveLetter;
            HealthStatus = $_.HealthStatus;
            DriveType = $_.DriveType;
            FileSystem = $_.FileSystem;
            FileSystemLabel = $_.FileSystemLabel;
            Path = $_.Path;
            PartitionNumber = $_.PartitionNumber;
            DiskNumber = $_.DiskNumber;
            Size = $_.Size;
            SizeRemaining = $_.SizeRemaining;
            IsSystem = $_.IsSystem;
            IsBoot = $_.IsBoot;
            IsActive = $_.IsActive;
        }
    
    if ($isDownlevel)
    {
        $volume.FileSystemType = $_.FileSystem;
    } 
    else {
    
        $volume.FileSystemType = $_.FileSystemType;
        $volume.OperationalStatus = $_.OperationalStatus;
        $volume.HealthStatus = $_.HealthStatus;
        $volume.DriveType = $_.DriveType;
        $volume.DedupMode = $_.DedupMode;
        $volume.UniqueId = $_.UniqueId;
        $volume.AllocationUnitSize = $_.AllocationUnitSize;
      
       }
    
       return $volume;
    }                                    
    
    #
    # Return results back to the caller.
    #
    if($VolumeId)
    {
        $resultantVolumes  | Where-Object {$_.Path -eq $resultantVolumes}
    }
    else
    {
        $resultantVolumes   
    }
    
    
}


<#
    
    .SYNOPSIS
        Script that gets temp folder based on the target node.
    
    .DESCRIPTION
        Script that gets temp folder based on the target node.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-TempFolder {
    #Get-ChildItem env: | where {$_.name -contains "temp"}
    Get-Childitem -Path Env:* | where-Object {$_.Name -eq "TEMP"}
}


<#
    
    .SYNOPSIS
        Gets the temporary folder (%temp%) for the user.
    
    .DESCRIPTION
        Gets the temporary folder (%temp%) for the user.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-TempFolderPath {
    Set-StrictMode -Version 5.0
    
    return $env:TEMP
}


<#
    
    .SYNOPSIS
        Gets temp folder based on the target node.
    
    .DESCRIPTION
        Gets temp folder based on the target node. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-TemporaryFolder {
    $ErrorActionPreference = "Stop"
    
    Get-Childitem -Path Env:* | where-Object {$_.Name -eq "TEMP"} 
}


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


<#

    .SYNOPSIS
        Script that imports certificate.

    .DESCRIPTION
        Script that imports certificate.

    .ROLE
        Administrators

#>
function Import-Certificate {
    param (
		[Parameter(Mandatory = $true)]
	    [String]
        $storePath,
        [Parameter(Mandatory = $true)]
	    [String]
        $filePath,
		[string]
        $exportable,
		[string]
		$password,
		[string]
		$invokeUserName,
		[string]
		$invokePassword
    )

    # Notes: invokeUserName and invokePassword are not used on this version. Remained for future use.

    $Script=@'
try {
	Import-Module PKI
	$params = @{ CertStoreLocation=$storePath; FilePath=$filePath }
    if ($password)
	{
		Add-Type -AssemblyName System.Security
		$encode = new-object System.Text.UTF8Encoding
		$encrypted = [System.Convert]::FromBase64String($password)
		$decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($encrypted, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
		$password = $encode.GetString($decrypted)
        $pwd = ConvertTo-SecureString -String $password -Force -AsPlainText
		$params.Password = $pwd
    }

    if($exportable -eq "Export")
	{
		$params.Exportable = $true;
    }

    Import-PfxCertificate @params | ConvertTo-Json | Out-File $ResultFile
} catch {
    $_.Exception.Message | ConvertTo-Json | Out-File $ErrorFile
}
'@

    if ([System.IO.Path]::GetExtension($filePath) -ne ".pfx") {
        Import-Module PKI
        Import-Certificate -CertStoreLocation $storePath -FilePath $filePath
        return;
    }

    # PFX private key handlings
    if ($password) {
        # encrypt password with current user.
        Add-Type -AssemblyName System.Security
        $encode =  new-object System.Text.UTF8Encoding
        $bytes = $encode.GetBytes($password)
        $encrypt = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
        $password = [System.Convert]::ToBase64String($encrypt)
    }

    # Pass parameters to script and generate script file in temp folder
    $ResultFile = $env:temp + "\import-certificate_result.json"
    $ErrorFile = $env:temp + "\import-certificate_error.json"
    if (Test-Path $ErrorFile) {
        Remove-Item $ErrorFile
    }

    if (Test-Path $ResultFile) {
        Remove-Item $ResultFile
    }

    $Script = '$storePath=' + "'$storePath';" +
            '$filePath=' + "'$filePath';" +
            '$exportable=' + "'$exportable';" +
            '$password=' + "'$password';" +
            '$ResultFile=' + "'$ResultFile';" +
            '$ErrorFile=' + "'$ErrorFile';" +
            $Script
    $ScriptFile = $env:temp + "\import-certificate.ps1"
    $Script | Out-File $ScriptFile

    # Create a scheduled task
    $TaskName = "SMEImportCertificate"

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
            if ($i -ge 3)
            {
                Write-EventLog -LogName Application -Source "SME Import certificate" -EntryType Error -EventID 1 -Message "Can't connect to Schedule service"
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
    if ($RootFolder.GetTasks(0) | Where-Object {$_.Name -eq $TaskName})
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

    #### example Start the task with user specified invoke username and password
    ####$Task.Principal.LogonType = 1
    ####$RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, $invokeUserName, $invokePassword, 1) | Out-Null

    #### Start the task with SYSTEM creds
    $RootFolder.RegisterTaskDefinition($TaskName, $Task, 6, "SYSTEM", $Null, 1) | Out-Null

    #Wait for running task finished
    $RootFolder.GetTask($TaskName).Run(0) | Out-Null
    while ($Scheduler.GetRunningTasks(0) | Where-Object {$_.Name -eq $TaskName})
    {
        Start-Sleep -s 2
    }

    #Clean up
    $RootFolder.DeleteTask($TaskName,0)
    Remove-Item $ScriptFile
    #Return result
    if (Test-Path $ErrorFile) {
        $result = Get-Content -Raw -Path $ErrorFile | ConvertFrom-Json
        Remove-Item $ErrorFile
        Remove-Item $ResultFile
        throw $result
    }

    if (Test-Path $ResultFile)
    {
        $result = Get-Content -Raw -Path $ResultFile | ConvertFrom-Json
        Remove-Item $ResultFile
        return $result
    }

}


<#
    
    .SYNOPSIS
        Imports registry from an external file.
    
    .DESCRIPTION
        Imports registry from an exteranl file. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Import-RegistryContent {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$file
        )
    
    $ErrorActionPreference = "Continue"
    $Error.Clear() 
    
    $LASTEXITCODE = 0      
    $tempFile = $env:TEMP + "\MsftSmeRegEditorImport.txt"
    
    Reg Import $file 2>$tempFile
    if ($LASTEXITCODE -ne 0) {
       throw  $Error[0].ToString()
    }
    
    Remove-Item $tempFile     
}


<#
    
    .SYNOPSIS
        Initializes a disk
    
    .DESCRIPTION
        Initializes a disk

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER diskNumber
        The disk number
    
    .PARAMETER partitionStyle
        The partition style
    
#>
function Initialize-StorageDisk {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $diskNumber,
    
        [Parameter(Mandatory = $true)]
        [String]
        $partitionStyle
    )
    
    Import-Module Storage
    
    Initialize-Disk -Number $diskNumber -PartitionStyle $partitionStyle
}


<#
    
    .SYNOPSIS
        Install device driver.
    
    .DESCRIPTION
        Install device driver.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Install-DeviceDriver {
    param(
        [String]$path
    )
    
    pnputil.exe -i -a $path
}


<#
    
    .SYNOPSIS
        Installs a Feature/Role/Role Service on the target server.
    
    .DESCRIPTION
        Installs a Feature/Role/Role Service on the target server, using Install-WindowsFeature PowerShell cmdlet.
        Returns a status object that contains the following properties:
            success - true/false depending on if the overall operation Succeeded
            status - status message
            result - response from Install-WindowsFeature call

        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER FeatureName
        Is a required parameter and is the name of the Role/Feature/Role Service to install
    
    .PARAMETER IncludeAllSubFeature
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .PARAMETER IncludeManagementTools
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .PARAMETER Restart
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .EXAMPLE
        # Installs the feature 'ManagementObject' without subfeature and management tools
        Install-RolesAndFeatures -FeatureName 'ManagementOData'
        
    .EXAMPLE
        # Installs the role 'Web-Server' with all dependencies and management tools
        Install-RolesAndFeatures -FeatureName 'Web-Server' -IncludeAllSubFeature -IncludeManagementTools
    
    
    .EXAMPLE
        # Installs the feature 'ManagementObject' without subfeature and management tools and reboots the server
        Install-RolesAndFeatures -FeatureName 'ManagementOData' -Restart
    
    .ROLE
        Administrators
    
#>
function Install-RolesAndFeatures {    
    param(
        [Parameter(Mandatory=$True)]
        [string[]]
        $FeatureName,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $IncludeAllSubFeature,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $IncludeManagementTools,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $Restart,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $WhatIf
    )
    
    Import-Module ServerManager
    
    Enum InstallStatus {
        Failed = 0
        Succeeded = 1
        NoSuchFeature = 2
        AlreadyInstalled = 3
        Pending = 4
    }
    
    $result  = $Null
    $status = $Null
    $success = $False
    
    $ErrorActionPreference = "Stop"
    
    $feature = Get-WindowsFeature -Name $FeatureName
    If ($feature) {
        If ($feature.Where({$_.InstallState -eq 'Available'})) {
            Try {
                $result = Install-WindowsFeature -Name $FeatureName -IncludeAllSubFeature:$IncludeAllSubFeature -IncludeManagementTools:$IncludeManagementTools -Restart:$Restart -WhatIf:$WhatIf
                $success = $result -AND $result.Success
                $status = if ($success) { [InstallStatus]::Succeeded } Else { [InstallStatus]::Failed }
            }
            Catch {
                If ($success -AND $Restart -AND $result.restartNeeded -eq 'Yes') {
                    $status = [InstallStatus]::Pending
                    $error.clear()
                } Else {
                    Throw
                }
            }
        } Else {
            $success = $True
            $status = [InstallStatus]::AlreadyInstalled
        }
    } Else {
        $success = $False
        $status = [InstallStatus]::NoSuchFeature
    }
    
    @{ 'success' = $success ; 'status' = $status ; 'result' = $result }
    
}


<#
    
    .SYNOPSIS
        Install File serve resource manager.
    
    .DESCRIPTION
        Install File serve resource manager.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Install-StorageFSRM {
    Import-Module ServerManager
    
    Install-WindowsFeature -Name FS-Resource-Manager -IncludeManagementTools
}


<#

    .SYNOPSIS
        Create a scheduled task to run a powershell script file to installs all available windows updates through ComObject, restart the machine if needed.

    .DESCRIPTION
        Create a scheduled task to run a powershell script file to installs all available windows updates through ComObject, restart the machine if needed.
        This is a workaround since CreateUpdateDownloader() and CreateUpdateInstaller() methods can't be called from a remote computer - E_ACCESSDENIED.
        More details see https://msdn.microsoft.com/en-us/library/windows/desktop/aa387288(v=vs.85).aspx

    .PARAMETER RestartTime
        The user-defined time to restart after update (Optional).

    .PARAMETER serverSelection
        Placeholder

    .ROLE
        Administrators

#>
function Install-WindowsUpdates {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $RestartTime,

        [Parameter(Mandatory = $true)]
        [int16]$serverSelection
    )

    $Script = @'
$objServiceManager = New-Object -ComObject 'Microsoft.Update.ServiceManager';
$objSession = New-Object -ComObject 'Microsoft.Update.Session';
$objSearcher = $objSession.CreateUpdateSearcher();
$objSearcher.ServerSelection = $serverSelection;
$serviceName = 'Windows Update';
$search = 'IsInstalled = 0';
$objResults = $objSearcher.Search($search);
$Updates = $objResults.Updates;
$FoundUpdatesToDownload = $Updates.Count;

$NumberOfUpdate = 1;
$objCollectionDownload = New-Object -ComObject 'Microsoft.Update.UpdateColl';
$updateCount = $Updates.Count;
Foreach($Update in $Updates)
{
	Write-Progress -Activity 'Downloading updates' -Status `"[$NumberOfUpdate/$updateCount]` $($Update.Title)`" -PercentComplete ([int]($NumberOfUpdate/$updateCount * 100));
	$NumberOfUpdate++;
	Write-Debug `"Show` update` to` download:` $($Update.Title)`" ;
	Write-Debug 'Accept Eula';
	$Update.AcceptEula();
	Write-Debug 'Send update to download collection';
	$objCollectionTmp = New-Object -ComObject 'Microsoft.Update.UpdateColl';
	$objCollectionTmp.Add($Update) | Out-Null;

	$Downloader = $objSession.CreateUpdateDownloader();
	$Downloader.Updates = $objCollectionTmp;
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

if($NeedsReboot){
	<#Restart immediately#>
	$waitTime = 0
    if($RestartTime) {
		<#Restart at given time#>
        $waitTime = [decimal]::round(((Get-Date $RestartTime) - (Get-Date)).TotalSeconds);
        if ($waitTime -lt 0 ) {
            $waitTime = 0
        }
		Shutdown -r -t $waitTime -c "SME installing Windows updates";
	}
}
'@

    #Pass parameters to script and generate script file in localappdata folder
    if ($RestartTime){
        $Script = '$RestartTime = ' + "'$RestartTime';" + $Script
    }
    $Script = '$serverSelection =' + "'$serverSelection';" + $Script

    $ScriptFile = $env:LocalAppData + "\Install-Updates.ps1"
    $Script | Out-File $ScriptFile
    if (-Not(Test-Path $ScriptFile)) {
        $message = "Failed to create file:" + $ScriptFile
        Write-Error $message
        return #If failed to create script file, no need continue just return here
    }

    #Create a scheduled task
    $TaskName = "SMEWindowsUpdateInstallUpdates"

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


<#
    
    .SYNOPSIS
        Attaches a VHD as disk.
    
    .DESCRIPTION
        Attaches a VHD as disk.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER path
        The VHD path
    
#>
function Mount-StorageVHD {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $path
    )
    
    Import-Module Storage
    
    Mount-DiskImage -ImagePath $path
}


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


<#
    
    .SYNOPSIS
        Creates a new process dump.
    
    .DESCRIPTION
        Creates a new process dump.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-CimProcessDump {
    Param(
    [System.UInt16]$ProcessId
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName MSFT_MTProcess -Key @('ProcessId') -Property @{ProcessId=$ProcessId;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName CreateDump
    
}


<#
    
    .SYNOPSIS
        Creates a new environment variable specified by name, type and data.
    
    .DESCRIPTION
        Creates a new environment variable specified by name, type and data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        return [Environment]::SetEnvironmentVariable($name, $value, $type)
    }
    Else {
        Write-Error "An environment variable of this name and type already exists."
    }
}


<#
    
    .SYNOPSIS
        Create a new Firewall Rule.
    
    .DESCRIPTION
        Create a new Firewall Rule.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-FirewallRule {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $displayName,
    
        [Parameter(Mandatory = $false)]
        [int]
        $action,
    
        [Parameter(Mandatory = $false)]
        [String]
        $description,
    
        [Parameter(Mandatory = $false)]
        [int]
        $direction,
    
        [Parameter(Mandatory = $false)]
        [bool]
        $enabled,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $icmpType,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $localAddresses,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $localPort,
    
        [Parameter(Mandatory = $false)]
        [String]
        $profile,
    
        [Parameter(Mandatory = $false)]
        [String]
        $protocol,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $remoteAddresses,
    
        [Parameter(Mandatory = $false)]
        [String[]]
        $remotePort
    )
    
    Import-Module netsecurity
    
    $command = 'New-NetFirewallRule -DisplayName $displayName'
    if ($action) {
        $command += ' -Action ' + $action;
    }
    if ($description) {
        $command += ' -Description $description';
    }
    if ($direction) {
        $command += ' -Direction ' + $direction;
    }
    if ($PSBoundParameters.ContainsKey('enabled')) {
        $command += ' -Enabled ' + $enabled;
    }
    if ($icmpType) {
        $command += ' -IcmpType $icmpType';
    }
    if ($localAddresses) {
        $command += ' -LocalAddress $localAddresses';
    }
    if ($localPort) {
        $command += ' -LocalPort $localPort';
    }
    if ($profile) {
        $command += ' -Profile $profile';
    }
    if ($protocol) {
        $command += ' -Protocol $protocol';
    }
    if ($remoteAddresses) {
        $command += ' -RemoteAddress $remoteAddresses';
    }
    if ($remotePort) {
        $command += ' -RemotePort $remotePort';
    }
    
    Invoke-Expression $command
    
}


<#
    
    .SYNOPSIS
        Create a new folder.
    
    .DESCRIPTION
        Create a new folder on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER Path
        String -- the path to the parent of the new folder.
    
    .PARAMETER NewName
        String -- the folder name.
    
#>
function New-Folder {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $NewName
    )
    
    Set-StrictMode -Version 5.0
    
    $pathSeparator = [System.IO.Path]::DirectorySeparatorChar;
    $newItem = New-Item -ItemType Directory -Path ($Path.TrimEnd($pathSeparator) + $pathSeparator + $NewName)
    
    return $newItem |
        Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                        @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                        Extension,
                        @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                        Name,
                        @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                        @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                        @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};
    
}


<#
    
    .SYNOPSIS
        Creates a new local group.
    
    .DESCRIPTION
        Creates a new local group. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016 but not Nano.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-LocalGroup {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $GroupName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Description
    )
    
    if (-not $Description) {
        $Description = ""
    }
    
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalGroup does NOT support downlevel and also with known bug
    $Error.Clear()
    try {
        $adsiConnection = [ADSI]"WinNT://localhost"
        $group = $adsiConnection.Create("Group", $GroupName)
        $group.InvokeSet("description", $Description)
        $group.SetInfo();
    }
    catch [System.Management.Automation.RuntimeException]
    { # if above block failed due to no ADSI (say in 2016Nano), use another cmdlet
        if ($_.Exception.Message -ne 'Unable to find type [ADSI].') {
            Write-Error $_.Exception.Message
            return
        }
        # clear existing error info from try block
        $Error.Clear()
        New-LocalGroup -Name $GroupName -Description $Description
    }    
}


<#
    
    .SYNOPSIS
        Creates a new local users.
    
    .DESCRIPTION
        Creates a new local users. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016 but not Nano.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-LocalUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $FullName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Description,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Password
    )
    
    if (-not $Description) {
        $Description = ""
    }
    
    if (-not $FullName) {
        $FullName = ""
    }
    
    if (-not $Password) {
        $Password = ""
    }
    
    # $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser does NOT support downlevel and also with known bug
    $Error.Clear()
    try {
        $adsiConnection = [ADSI]"WinNT://localhost"
        $user = $adsiConnection.Create("User", $UserName)
        if ($Password) {
            $user.setpassword($Password)
        }
        $user.InvokeSet("fullName", $FullName)
        $user.InvokeSet("description", $Description)
        $user.SetInfo();
    }
    catch [System.Management.Automation.RuntimeException]
    { # if above block failed due to no ADSI (say in 2016Nano), use another cmdlet
        if ($_.Exception.Message -ne 'Unable to find type [ADSI].') {
            Write-Error $_.Exception.Message
            return
        }
        # clear existing error info from try block
        $Error.Clear()
        if ($Password) {
            #Found a bug where the cmdlet will create a user even if the password is not strong enough
            $securePasswordString = ConvertTo-SecureString -String $Password -AsPlainText -Force;
            New-LocalUser -Name $UserName -FullName $FullName -Description $Description -Password $securePasswordString;
        }
        else {
            New-LocalUser -Name $UserName -FullName $FullName -Description $Description -NoPassword;
        }
    }    
}


<#

    .SYNOPSIS
        Creates the mini dump of the process on downlevel computer.

    .DESCRIPTION
        Creates the mini dump of the process on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function New-ProcessDumpDownlevel {
    param
    (
        # The process ID of the process whose mini dump is supposed to be created.
        [int]
        $processId,

        # Path to the process dump file name.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $fileName
    )

    $NativeCode = @"

namespace SME
{
    using System;
    using System.Runtime.InteropServices;

    public static class ProcessMiniDump
    {
        private enum MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000
        };

        [DllImport("dbghelp.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        private extern static bool MiniDumpWriteDump(
            System.IntPtr hProcess,
            int processId,
            Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
            MINIDUMP_TYPE dumpType,
            System.IntPtr exceptionParam,
            System.IntPtr userStreamParam,
            System.IntPtr callbackParam);

        public static void Create(int processId, string fileName)
        {
            if(string.IsNullOrWhiteSpace(fileName))
            {
                throw new ArgumentNullException(fileName);
            }

            if(processId < 0)
            {
                throw new ArgumentException("Incorrect value of ProcessId", "processId");
            }

            System.IO.FileStream fileStream = null;

            try
            {
                fileStream = System.IO.File.OpenWrite(fileName);

                bool sucess = MiniDumpWriteDump(
                    System.Diagnostics.Process.GetCurrentProcess().Handle,
                    processId,
                    fileStream.SafeFileHandle,
                    MINIDUMP_TYPE.MiniDumpWithFullMemory | MINIDUMP_TYPE.MiniDumpWithFullMemoryInfo | MINIDUMP_TYPE.MiniDumpWithHandleData | MINIDUMP_TYPE.MiniDumpWithUnloadedModules | MINIDUMP_TYPE.MiniDumpWithThreadInfo,
                    System.IntPtr.Zero,
                    System.IntPtr.Zero,
                    System.IntPtr.Zero);

                if (!sucess)
                {
                    Marshal.ThrowExceptionForHR(Marshal.GetHRForLastWin32Error());
                }
            }
            finally
            {
                if(fileStream != null)
                {
                    fileStream.Close();
                }
            }
        }
    }
}
"@

    ############################################################################################################################

    # Global settings for the script.

    ############################################################################################################################

    $ErrorActionPreference = "Stop"

    Set-StrictMode -Version 3.0

    ############################################################################################################################

    # Main script.

    ############################################################################################################################

    Add-Type -TypeDefinition $NativeCode
    Remove-Variable NativeCode

    $fileName = "$($env:temp)\$($fileName)"

    try {
        # Create the mini dump using native call.
        try {
            [SME.ProcessMiniDump]::Create($processId, $fileName)
            $result = New-Object PSObject
            $result | Add-Member -MemberType NoteProperty -Name 'DumpFilePath' -Value $fileName
            $result
        }
        catch {
            if ($_.FullyQualifiedErrorId -eq "ArgumentException") {
                throw "Unable to create the mini dump of the process. Please make sure that the processId is correct and the user has required permissions to create the mini dump of the process."
            }
            elseif ($_.FullyQualifiedErrorId -eq "UnauthorizedAccessException") {
                throw "Access is denied. User does not relevant permissions to create the mini dump of process with ID: {0}" -f $processId
            }
            else {
                throw
            }
        }
    }
    finally {
        if (Test-Path $fileName) {
            if ((Get-Item $fileName).length -eq 0) {
                # Delete the zero byte file.
                Remove-Item -Path $fileName -Force -ErrorAction Stop
            }
        }
    }
}


<#
    
    .SYNOPSIS
        Add new key based on the parent key path.
    
    .DESCRIPTION
        Add new key based on the parent key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-RegistryKey {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$Newkey
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()    
    New-Item -Path $path -Name $Newkey
    
}


<#
    
    .SYNOPSIS
        Adds new value based on the selected key.
    
    .DESCRIPTION
        Adds new value based on the selected key. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function New-RegistryValue {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$name,
        [Parameter(Mandatory = $true) ]    
        [int]$valueType,
        [Parameter(Mandatory = $false)]
        [String]$value,
        [Parameter(Mandatory = $false)]
        [byte[]]$valueBytes           
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()       
    if ($valueType -eq 3){
        New-ItemProperty -Path $path -Name $name -Value $valueBytes -PropertyType $valueType
    }    
    else{
        New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $valueType
    }
    
}


<#
    
    .SYNOPSIS
        Creates a new Quota for volume.
    
    .DESCRIPTION
        Creates a new Quota for volume.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER disabledQuota
        Enable or disable quota.
    
    .PARAMETER path
        Path of the quota.
    
    .PARAMETER size
        The size of quota.
    
    .PARAMETER softLimit
        Deny if usage exceeding quota limit.
    
#>
function New-StorageQuota {
    param
    (
        # Enable or disable quota.
        [Boolean]
        $disabledQuota,
    
        # Path of the quota.
        [String]
        $path,
    
        # The size of quota.
        [String]
        $size,
    
        # Deny if usage exceeding quota limit.
        [Boolean]
        $softLimit
    )
    
    Import-Module FileServerResourceManager
    
    $scriptArgs = @{
        Path = $path;
    }
    
    if ($size) {
        $scriptArgs.Size = $size
    }
    if ($disabledQuota) {
        $scriptArgs.Disabled = $true
    }
    if ($softLimit) {
        $scriptArgs.SoftLimit = $true
    }
    
    New-FsrmQuota @scriptArgs
}


<#

    .SYNOPSIS
        Creates a new VHD.

    .DESCRIPTION
        Creates a new VHD.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

    .PARAMETER filePath
        The path to the VHD that will be created.

    .PARAMETER size
        The size of the VHD.

    .PARAMETER dynamic
        True for a dynamic VHD, false otherwise.

    .PARAMETER overwrite
        True to overwrite an existing VHD.

#>
function New-StorageVHD {
    param
    (
        # Path to the resultant vhd/vhdx file name.
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $filepath,

        # The size of vhd/vhdx.
        [Parameter(Mandatory = $true)]
        [System.UInt64]
        $size,

        # Whether it is a dynamic vhd/vhdx.
        [Parameter(Mandatory = $true)]
        [Boolean]
        $dynamic,

        # Overwrite if already exists.
        [Boolean]
        $overwrite=$false
    )

    $NativeCode = @"
namespace SME
{
    using Microsoft.Win32.SafeHandles;
    using System;
    using System.ComponentModel;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Security;

    public static class VirtualDisk
    {
        const uint ERROR_SUCCESS = 0x0;

        const uint DEFAULT_SECTOR_SIZE = 0x200;

        const uint DEFAULT_BLOCK_SIZE = 0x200000;

        private static Guid VirtualStorageTypeVendorUnknown = new Guid("00000000-0000-0000-0000-000000000000");

        private static Guid VirtualStorageTypeVendorMicrosoft = new Guid("EC984AEC-A0F9-47e9-901F-71415A66345B");

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SecurityDescriptor
        {
            public byte revision;
            public byte size;
            public short control;
            public IntPtr owner;
            public IntPtr group;
            public IntPtr sacl;
            public IntPtr dacl;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CreateVirtualDiskParametersV1
        {
            public CreateVirtualDiskVersion Version;
            public Guid UniqueId;
            public ulong MaximumSize;
            public uint BlockSizeInBytes;
            public uint SectorSizeInBytes;
            public string ParentPath;
            public string SourcePath;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct CreateVirtualDiskParametersV2
        {
            public CreateVirtualDiskVersion Version;
            public Guid UniqueId;
            public ulong MaximumSize;
            public uint BlockSizeInBytes;
            public uint SectorSizeInBytes;
            public uint PhysicalSectorSizeInBytes;
            public string ParentPath;
            public string SourcePath;
            public OpenVirtualDiskFlags OpenFlags;
            public VirtualStorageType ParentVirtualStorageType;
            public VirtualStorageType SourceVirtualStorageType;
            public Guid ResiliencyGuid;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct VirtualStorageType
        {
            public VirtualStorageDeviceType DeviceId;
            public Guid VendorId;
        }

        public enum CreateVirtualDiskVersion : int
        {
            VersionUnspecified = 0x0,
            Version1 = 0x1,
            Version2 = 0x2
        }

        public enum VirtualStorageDeviceType : int
        {
            Unknown = 0x0,
            Iso = 0x1,
            Vhd = 0x2,
            Vhdx = 0x3
        }

        [Flags]
        public enum OpenVirtualDiskFlags
        {
            None = 0x0,
            NoParents = 0x1,
            BlankFile = 0x2,
            BootDrive = 0x4,
        }

        [Flags]
        public enum VirtualDiskAccessMask
        {
            None = 0x00000000,
            AttachReadOnly = 0x00010000,
            AttachReadWrite = 0x00020000,
            Detach = 0x00040000,
            GetInfo = 0x00080000,
            Create = 0x00100000,
            MetaOperations = 0x00200000,
            Read = 0x000D0000,
            All = 0x003F0000,
            Writable = 0x00320000
        }

        [Flags]
        public enum CreateVirtualDiskFlags
        {
            None = 0x0,
            FullPhysicalAllocation = 0x1
        }

        [DllImport("virtdisk.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint CreateVirtualDisk(
            [In, Out] ref VirtualStorageType VirtualStorageType,
            [In]          string Path,
            [In]          VirtualDiskAccessMask VirtualDiskAccessMask,
            [In, Out] ref SecurityDescriptor SecurityDescriptor,
            [In]          CreateVirtualDiskFlags Flags,
            [In]          uint ProviderSpecificFlags,
            [In, Out] ref CreateVirtualDiskParametersV2 Parameters,
            [In]          IntPtr Overlapped,
            [Out]     out SafeFileHandle Handle);

        [DllImport("advapi32", SetLastError = true)]
        public static extern bool InitializeSecurityDescriptor(
            [Out]     out SecurityDescriptor pSecurityDescriptor,
            [In]          uint dwRevision);


        public static void Create(string path, ulong size, bool dynamic, bool overwrite)
        {
            if(string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentNullException("path");
            }

            // Validate size.  It needs to be a multiple of 512...  
            if ((size % 512) != 0)
            {
                throw (
                    new ArgumentOutOfRangeException(
                        "size",
                        size,
                        "The size of the virtual disk must be a multiple of 512."));
            }

            bool isVhd = false;

            VirtualStorageType virtualStorageType = new VirtualStorageType();
            virtualStorageType.VendorId = VirtualStorageTypeVendorMicrosoft;

            if (Path.GetExtension(path) == ".vhdx")
            {
                virtualStorageType.DeviceId = VirtualStorageDeviceType.Vhdx;
            }
            else if (Path.GetExtension(path) == ".vhd")
            {
                virtualStorageType.DeviceId = VirtualStorageDeviceType.Vhd;

                isVhd = true;
            }
            else
            {
                throw new ArgumentException("The path should have either of the following two extensions: .vhd or .vhdx");
            }

            if ((overwrite) && (System.IO.File.Exists(path)))
            {
                System.IO.File.Delete(path);
            }

            CreateVirtualDiskParametersV2 createParams = new CreateVirtualDiskParametersV2();
            createParams.Version = CreateVirtualDiskVersion.Version2;
            createParams.UniqueId = Guid.NewGuid();
            createParams.MaximumSize = size;
            createParams.BlockSizeInBytes = 0;
            createParams.SectorSizeInBytes = DEFAULT_SECTOR_SIZE;
            createParams.PhysicalSectorSizeInBytes = 0;
            createParams.ParentPath = null;
            createParams.SourcePath = null;
            createParams.OpenFlags = OpenVirtualDiskFlags.None;
            createParams.ParentVirtualStorageType = new VirtualStorageType();
            createParams.SourceVirtualStorageType = new VirtualStorageType();

            if(isVhd && dynamic)
            {
                createParams.BlockSizeInBytes = DEFAULT_BLOCK_SIZE;
            }

            CreateVirtualDiskFlags flags;

            if (dynamic)
            {
                flags = CreateVirtualDiskFlags.None;
            }
            else
            {
                flags = CreateVirtualDiskFlags.FullPhysicalAllocation;
            }

            SecurityDescriptor securityDescriptor;

            if (!InitializeSecurityDescriptor(out securityDescriptor, 1))
            {
                throw (
                    new SecurityException(
                        "Unable to initialize the security descriptor for the virtual disk."
                ));
            }

            SafeFileHandle vhdHandle = null;

            try
            {
                uint returnCode = CreateVirtualDisk(
                    ref virtualStorageType,
                        path,
                        VirtualDiskAccessMask.None,
                    ref securityDescriptor,
                        flags,
                        0,
                    ref createParams,
                        IntPtr.Zero,
                    out vhdHandle);

                if (ERROR_SUCCESS != returnCode)
                {
                    throw (new Win32Exception((int)returnCode));
                }
            }
            finally
            {
                if (vhdHandle != null && !vhdHandle.IsClosed)
                {
                    vhdHandle.Close();
                    vhdHandle.SetHandleAsInvalid();
                }
            }
        }
    }
}
"@

    ############################################################################################################################

    # Global settings for the script.

    ############################################################################################################################

    $ErrorActionPreference = "Stop"

    Set-StrictMode -Version 3.0

    Import-Module -Name Storage -Force -Global -WarningAction SilentlyContinue
    Import-Module Microsoft.PowerShell.Utility

    ############################################################################################################################

    # Main script.

    ############################################################################################################################

    Add-Type -TypeDefinition $NativeCode
    Remove-Variable NativeCode

    # Resolve $abc and ..\ from the File path.
    $filepath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($ExecutionContext.InvokeCommand.ExpandString($filepath))

    # Create the virtual disk drive.
    try
    {
        [SME.VirtualDisk]::Create($filepath, $size, $dynamic, $overwrite)
    }
    catch
    {
        if($_.Exception.InnerException)
        {
            throw $_.Exception.InnerException
        }
        elseif($_.Exception)
        {
            throw $_.Exception
        }
        else
        {
            throw $_
        }
    }

    # Mount the virtual disk drive.
    Mount-DiskImage -ImagePath $filepath


}


<#
    
    .SYNOPSIS
        Creates a volume.
    
    .DESCRIPTION
        Creates a volume.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER diskNumber
        The disk number.
    
    .PARAMETER driveLetter
        The drive letter.
    
    .PARAMETER sizeInBytes
        The size in bytes.
    
    .PARAMETER fileSystem
        The file system.
    
    .PARAMETER allocationUnitSizeInBytes
        The allocation unit size.
    
    .PARAMETER fileSystemLabel
        The file system label.
    
    .PARAMETER useMaxSize
        True to use the maximum size.
    
#>
function New-StorageVolume {
    param (
        [parameter(Mandatory=$true)]
        [String]
        $diskNumber,
        [parameter(Mandatory=$true)]
        [Char]
        $driveLetter,
        [uint64]
        $sizeInBytes,
        [parameter(Mandatory=$true)]
        [string]
        $fileSystem,
        [parameter(Mandatory=$true)]
        [uint32]
        $allocationUnitSizeInBytes,
        [string]
        $fileSystemLabel,
        [boolean]
        $useMaxSize = $false
    )
    
    Import-Module Microsoft.PowerShell.Management
    Import-Module Microsoft.PowerShell.Utility
    Import-Module Storage
    
    # This is a work around for getting rid of format dialog on the machine when format fails for reasons. Get rid of this code once we make changes on the UI to identify correct combinations.
    $service = Get-WmiObject -Class Win32_Service -Filter "Name='ShellHWDetection'" -ErrorAction SilentlyContinue | out-null
    if($service) 
    {
        $service.StopService();
    }
    
    
    if ($useMaxSize)
    {
        $p = New-Partition -DiskNumber $diskNumber -DriveLetter $driveLetter -UseMaximumSize
    } 
    else
    {
        $p = New-Partition -DiskNumber $diskNumber -DriveLetter $driveLetter -Size $sizeInBytes
    }
    
    # Format only when partition is created
    if ($p)
    {
        Format-Volume -DriveLetter $driveLetter -FileSystem $fileSystem -NewFileSystemLabel "$fileSystemLabel" -AllocationUnitSize $allocationUnitSizeInBytes -confirm:$false
        # TODO: Catch exception that occur with race condition. We don't have specific exception details as unable to repro. 
        # For now surface any exception that occur here to the UI.
    }
    
    if($service) 
    {
        $service.StartService();
    }
    
    $volume = Get-Volume -DriveLetter $driveLetter
    
    if ($volume.FileSystemLabel) { 
        $volumeName = $volume.FileSystemLabel + " (" + $volume.DriveLetter + ":)"
    } else { 
        $volumeName = "(" + $volume.DriveLetter + ":)"
    }
    
    return @{ 
        Name = $volumeName;
        HealthStatus = $volume.HealthStatus;
        DriveType = $volume.DriveType;
        DriveLetter = $volume.DriveLetter;
        FileSystem = $volume.FileSystem;
        FileSystemLabel = $volume.FileSystemLabel;
        Path = $volume.Path;
        Size = $volume.Size;
        SizeRemaining = $volume.SizeRemaining;
    }
}


<#
    
    .SYNOPSIS
        Removes all shares of a folder.
    
    .DESCRIPTION
        Removes all shares of a folder.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder.
    
#>
function Remove-AllShareNames {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path    
    )
    
    Set-StrictMode -Version 5.0
    
    $CimInstance = Get-CimInstance -Class Win32_Share -Filter Path="'$Path'"
    $RemoveShareCommand = ''
    if ($CimInstance.name -And $CimInstance.name.GetType().name -ne 'String') { $RemoveShareCommand = $CimInstance.ForEach{ 'Remove-SmbShare -Name ' + $_.name + ' -Force'} } 
    Else { $RemoveShareCommand = 'Remove-SmbShare -Name ' + $CimInstance.Name + ' -Force'}
    if($RemoveShareCommand) { $RemoveShareCommand.ForEach{ Invoke-Expression $_ } }    
}


<#
   
    .SYNOPSIS
        Script that deletes certificate.
   
    .DESCRIPTION
        Script that deletes certificate.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
   
    .ROLE
        Administrators

#>
function Remove-Certificate {
    param (
       [Parameter(Mandatory = $true)]
       [string]$thumbprintPath
    )
   
   Get-ChildItem $thumbprintPath | Remove-Item
   
}


<#
    .SYNOPSIS
        Removes an environment variable specified by name and type.
    
    .DESCRIPTION
        Removes an environment variable specified by name and type.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $name,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    If ([Environment]::GetEnvironmentVariable($name, $type) -eq $null) {
        Write-Error "An environment variable of this name and type does not exist."
    }
    Else {
        [Environment]::SetEnvironmentVariable($name, $null, $type)
    }
}


<#
    
    .SYNOPSIS
        Deletes file based on the path.
    
    .DESCRIPTION
        Deletes file based on the path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-FilePath {
    Param([string]$path)
    
    $ErrorActionPreference = "Stop"
    
    Microsoft.PowerShell.Management\Remove-Item -Path $path;
}


<#
    
    .SYNOPSIS
        Remove the passed in file or path.
    
    .DESCRIPTION
        Remove the passed in file or path from this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER path
        String -- the file or path to remove.
    
#>
function Remove-FileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
    Remove-Item -Path $Path -Confirm:$false -Force -Recurse
}


<#
    
    .SYNOPSIS
        Delete Firewall rule.
    
    .DESCRIPTION
        Delete Firewall rule.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-FirewallRule {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $instanceId,
    
        [Parameter(Mandatory = $true)]
        [String]
        $policyStore
    )
    
    Import-Module netsecurity
    
    Remove-NetFirewallRule -PolicyStore $policyStore -Name $instanceId
    
}


<#
    
    .SYNOPSIS
        Removes a user from the folder access.
    
    .DESCRIPTION
        Removes a user from the folder access.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- The path to the folder.
    
    .PARAMETER Identity
        String -- The user identification (AD / Local user).
    
    .PARAMETER FileSystemRights
        String -- File system rights of the user.
    
#>
function Remove-FolderShareUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $Identity,
    
        [Parameter(Mandatory = $true)]
        [String]
        $FileSystemRights
    )
    
    Set-StrictMode -Version 5.0
    
    $Acl = Get-Acl $Path
    $AccessRule = New-Object system.security.accesscontrol.filesystemaccessrule($Identity, $FileSystemRights,'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $Acl.RemoveAccessRuleAll($AccessRule)
    Set-Acl $Path $Acl
    
}


<#
    
    .SYNOPSIS
        Script that deletes certificate based on the path.
    
    .DESCRIPTION
        Script that deletes certificate based on the path.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators
    
#>
function Remove-ItemByPath {
    Param([string]$path)
    
    Remove-Item -Path $path;
}


<#
    
    .SYNOPSIS
        Delete a local group.
    
    .DESCRIPTION
        Delete a local group. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-LocalGroup {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $GroupName
    )
    
    try {
        $adsiConnection = [ADSI]"WinNT://localhost";
        $adsiConnection.Delete("Group", $GroupName);
    }
    catch {
        # Instead of _.Exception.Message, InnerException.Message is more meaningful to end user
        Write-Error $_.Exception.InnerException.Message
        $Error.Clear()
    }    
}


<#
    
    .SYNOPSIS
        Delete a local user.
    
    .DESCRIPTION
        Delete a local user. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-LocalUser {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName
    )
    
    try {
        $adsiConnection = [ADSI]"WinNT://localhost";
        $adsiConnection.Delete("User", $UserName);
    }
    catch {
        # Instead of _.Exception.Message, InnerException.Message is more meaningful to end user
        Write-Error $_.Exception.InnerException.Message
        $Error.Clear()
    }
}


<#
    
    .SYNOPSIS
        Removes a local user from one or more local groups.
    
    .DESCRIPTION
        Removes a local user from one or more local groups. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-LocalUserFromLocalGroups {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName,
    
        [Parameter(Mandatory = $true)]
        [String[]]
        $GroupNames
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."
    $Error.Clear()
    $message = ""
    $results = @()
    if (!$isWinServer2016OrNewer) {
        $objUser = "WinNT://$UserName,user"
    }
    Foreach ($group in $GroupNames) {
        if ($isWinServer2016OrNewer) {
            # If execute an external command, the following steps to be done to product correct format errors:
            # -	Use "2>&1" to store the error to the variable.
            # -	Watch $Error.Count to determine the execution result.
            # -	Concatinate the error message to single string and sprit out with Write-Error.
            $Error.Clear()
            $result = & 'net' localgroup $group $UserName /delete 2>&1
            # $LASTEXITCODE here does not return error code, have to use $Error
            if ($Error.Count -ne 0) {
                foreach($item in $result) {
                    if ($item.Exception.Message.Length -gt 0) {
                        $message += $item.Exception.Message
                    }
                }
                $Error.Clear()
                Write-Error $message
            }
        }
        else {
            $objGroup = [ADSI]("WinNT://localhost/$group,group")
            $objGroup.Remove($objUser)
        }
    }    
}


<#
    
    .SYNOPSIS
        Deletes a selected key path.
    
    .DESCRIPTION
        Deletes a selected key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-RegistryKey {
    Param([string]$path)
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()   
    Microsoft.PowerShell.Management\Remove-Item -Path $path -Recurse
}


<#
    
    .SYNOPSIS
        Deletes a selected Value based on the selected key path.
    
    .DESCRIPTION
        Deletes a selected Value based on the selected key path. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-RegistryValue {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$ValueName
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()       
    Remove-itemproperty -path $path -name $ValueName    
}


<#
    
    .SYNOPSIS
        Script to delete a scheduled tasks.
    
    .DESCRIPTION
        Script to delete a scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-ScheduledTask {
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $true)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    ScheduledTasks\Unregister-ScheduledTask -TaskPath $taskPath -TaskName $taskName -Confirm:$false
    
}


<#
    
    .SYNOPSIS
        Removes action from scheduled task actions.
    
    .DESCRIPTION
        Removes action from scheduled task actions.

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
function Remove-ScheduledTaskAction {
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
    
    
    ######################################################
    #### Main script
    ######################################################
    
    $task = Get-ScheduledTask -TaskName $taskName -TaskPath $taskPath
    $actionsArray =  @()
    
    $task.Actions| ForEach-Object {
        $matched = $true;  
      
        if( -not ([string]::IsNullOrEmpty($_.Arguments) -and [string]::IsNullOrEmpty($actionArguments)))
        {
            if ($_.Arguments -ne $actionArguments)
            {
                $matched = $false;
            }
        }
    
        $workingDirectoryMatched  = $true;
        if( -not ([string]::IsNullOrEmpty($_.WorkingDirectory) -and [string]::IsNullOrEmpty($workingDirectory)))
        {
            if ($_.WorkingDirectory -ne $workingDirectory)
            {
                $matched = $false;
            }
        }
    
        $executeMatched  = $true;
        if ($_.Execute -ne $actionExecute) 
        {
              $matched = $false;
        }
    
        if (-not ($matched))
        {
            $actionsArray += $_;
        }
    }
    
    
    Set-ScheduledTask -TaskName $taskName -TaskPath $taskPath -Action $actionsArray
}


<#
    
    .SYNOPSIS
        Remove Quota with the path.
    
    .DESCRIPTION
        Remove Quota with the path.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER path
        Path of the quota.
#>
function Remove-StorageQuota {
    param
    (
        # Path of the quota.
        [String]
        $path
    )
    Import-Module FileServerResourceManager
    
    Remove-FsrmQuota -Path $path -Confirm:$false
}


<#
    
    .SYNOPSIS
        Remove a volume.
    
    .DESCRIPTION
        Remove a volume.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER driveLetter
        The drive letter.
    
#>
function Remove-StorageVolume {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $driveLetter
    )
    Import-Module Storage
    
    Remove-Partition -DriveLetter $driveLetter -Confirm:$false    
}


<#
    
    .SYNOPSIS
        Removes local or domain users from the local group.
    
    .DESCRIPTION
        Removes local or domain users from the local group. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Remove-UsersFromLocalGroup {
    param (
        [Parameter(Mandatory = $true)]
        [String[]]
        $users,
    
        [Parameter(Mandatory = $true)]
        [String]
        $group
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile net localgroup do NOT support downlevel "net : System error 1312 has occurred."
    
    $message = ""
    Foreach ($user in $users) {
        if ($isWinServer2016OrNewer) {
            # If execute an external command, the following steps to be done to product correct format errors:
            # -	Use "2>&1" to store the error to the variable.
            # -	Watch $Error.Count to determine the execution result.
            # -	Concatinate the error message to single string and sprit out with Write-Error.
            $Error.Clear()
            $result = & 'net' localgroup $group $user /delete 2>&1
            # $LASTEXITCODE here does not return error code, have to use $Error
            if ($Error.Count -ne 0) {
                foreach($item in $result) {
                    if ($item.Exception.Message.Length -gt 0) {
                        $message += $item.Exception.Message
                    }
                }
                $Error.Clear()
                Write-Error $message
            }
        }
        else {
            if ($user -like '*\*') { # domain user
                $user = $user.Replace('\', '/')
            }
            $groupInstance = [ADSI]("WinNT://localhost/$group,group")
            $groupInstance.Remove("WinNT://$user,user")
        }
    }    
}


<#
    
    .SYNOPSIS
        Rename a folder.
    
    .DESCRIPTION
        Rename a folder on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER Path
        String -- the path to the folder.
    
    .PARAMETER NewName
        String -- the new folder name.
    
#>
function Rename-FileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $NewName
    )
    
    Set-StrictMode -Version 5.0
    
    <#
    .Synopsis
        Name: Get-FileSystemEntityType
        Description: Gets the type of a local file system entity.
    
    .Parameters
        $Attributes: The System.IO.FileAttributes of the FileSystemEntity.
    
    .Returns
        The type of the local file system entity.
    #>
    function Get-FileSystemEntityType
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.IO.FileAttributes]
            $Attributes
        )
    
        if ($Attributes -match "Directory" -or $Attributes -match "ReparsePoint")
        {
            return "Folder";
        }
        else
        {
            return "File";
        }
    }
    
    Rename-Item -Path $Path -NewName $NewName -PassThru |
        Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                    @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                    Extension,
                    @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                    Name,
                    @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                    @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                    @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};
    
}


<#

    .SYNOPSIS
        Renames a local group.

    .DESCRIPTION
        Renames a local group. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016 but not Nano.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function Rename-LocalGroup {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $GroupName,

        [Parameter(Mandatory = $true)]
        [String]
        $NewGroupName
    )


    # ADSI does NOT support 2016 Nano, meanwhile Rename-LocalGroup does NOT support downlevel and also with known bug
    $Error.Clear()
    try {
        $adsiConnection = [ADSI]"WinNT://localhost"
        $group = $adsiConnection.Children.Find($GroupName, "Group")
        if ($group) {
            $group.psbase.rename($NewGroupName)
            $group.psbase.CommitChanges()
        }
    }
    catch [System.Management.Automation.RuntimeException]
    { # if above block failed due to no ADSI (say in 2016Nano), use another cmdlet
        if ($_.Exception.Message -ne 'Unable to find type [ADSI].') {
            Write-Error $_.Exception.Message
            return
        }
        # clear existing error info from try block
        $Error.Clear()
        Rename-LocalGroup -Name $GroupName -NewGroupName $NewGroupName
    }

}


<#
    
    .SYNOPSIS
        Renames a selected key.
    
    .DESCRIPTION
        Renames a selected key. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Rename-RegistryKey {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$NewName
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()       
    Rename-Item -Path $path -NewName $NewName
}


<#
    
    .SYNOPSIS
        Renames value based on the selected key.
    
    .DESCRIPTION
        Renames value based on the selected key. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Rename-RegistryValue {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$name,
        [Parameter(Mandatory = $true)]
        [String]$newName  
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()       
    Rename-ItemProperty -Path $path -Name $name -NewName $newName
}


<#
    
    .SYNOPSIS
        Resizes the volume.
    
    .DESCRIPTION
        Resizes the volume.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER driveLetter
        The drive letter.
    
    .PARAMETER newSize
        The new size.
    
#> 
function Resize-StorageVolume {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $driveLetter,
    
        [UInt64]
        $newSize
    
    )
    
    Import-Module Storage
    
    Resize-Partition -DriveLetter $driveLetter -Size $newSize
}


<#
    
    .SYNOPSIS
        Reboot Windows Operating System by using Win32_OperatingSystem provider.
    
    .DESCRIPTION
        Reboot Windows Operating System by using Win32_OperatingSystem provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Restart-CimOperatingSystem {
    Param(
    )
    
    import-module CimCmdlets
    
    Invoke-CimMethod -Namespace root/cimv2 -ClassName Win32_OperatingSystem -MethodName Reboot
    
}


<#
    
    .SYNOPSIS
        Resume a service using CIM Win32_Service class.
    
    .DESCRIPTION
        Resume a service using CIM Win32_Service class.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Resume-CimService {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName ResumeService
}


<#
    
    .SYNOPSIS
        Search Registry key, value name, value data under the selected key.
    
    .DESCRIPTION
        Search Registry key, value name, value data under the selected key. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers
    
#>
function Search-RegistryKeyAndValue {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$SearchTerm
        )
    
    $ErrorActionPreference = "Stop"    
                    
    $global:results = @()
    $Error.Clear()                   
    function CreateEntry([string] $entryName, [string] $entryType ='', [string] $entryData=''){
        $valueEntry = New-Object System.Object
        $valueEntry | Add-Member -type NoteProperty -name Name -value $entryName  
    
        $valueEntry | Add-Member -type NoteProperty -name type -value $entryType
        $valueEntry | Add-Member -type NoteProperty -name data -value  $entryData
        return $valueEntry
    }
    
    function SearchRegKeyValue([object] $Keys){
        foreach ($Key in $Keys){
            if ($Key.PSChildName -match $SearchTerm) {  
                $global:results += CreateEntry $key.PSPath 
            }  
    
            $valueNames = $Key.GetValueNames()
            foreach($valName in $valueNames){
                if ($valName -match $SearchTerm) {  
                    $valPath = $key.PSPath + '\\'+ $valName
                    $global:results += CreateEntry $valPath $key.GetValueKind($valName) $key.GetValue($valName)
                }  
    
                if (($valName | % { $Key.GetValue($_) }) -match $SearchTerm) {  
                    $valPath = $key.PSPath + '\\'+ $valName
                    $global:results += CreateEntry $valPath $key.GetValueKind($valName) $key.GetValue($valName)
                } 
            } 
        }
    }
    
    $curItem = Get-Item $path
    SearchRegKeyValue $curItem 
    
    $childItems = Get-ChildItem $path -ErrorAction SilentlyContinue -Recurse
    SearchRegKeyValue $childItems 
    
    $global:results    
}


<#
    
    .SYNOPSIS
        Script that set windows update automatic update options in registry key.
    
    .DESCRIPTION
        Script that set windows update automatic update options in registry key.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .EXAMPLE
        Set AUoptions
        PS C:\> Set-AUoptions "2"
    
    .ROLE
        Administrators
    
#>
function Set-AutomaticUpdatesOptions {
    Param(
    [Parameter(Mandatory = $true)]
    [string]$AUOptions
    )
    
    $Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    switch($AUOptions)
    {
        '0' # Not defined, delete registry folder if exist
            {
                if (Test-Path $Path) {
                    Remove-Item $Path
                }
            }
        '1' # Disabled, set NoAutoUpdate to 1 and delete AUOptions if existed
            {
                if (Test-Path $Path) {
                    Set-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x1 -Force
                    Remove-ItemProperty -Path $Path -Name AUOptions
                }
                else {
                    New-Item $Path -Force
                    New-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x1 -Force
                }
            }
        default # else 2-5, set AUoptions
            {
                 if (!(Test-Path $Path)) {
                     New-Item $Path -Force
                }
                Set-ItemProperty -Path $Path -Name AUOptions -Value $AUOptions -Force
                Set-ItemProperty -Path $Path -Name NoAutoUpdate -Value 0x0 -Force
            }
    }
    
}


<#
    
    .SYNOPSIS
        Sets a computer and/or its domain/workgroup information.
    
    .DESCRIPTION
        Sets a computer and/or its domain/workgroup information.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ComputerIdentification {
    param(
        [Parameter(Mandatory = $False)]
        [string]
        $ComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewComputerName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Domain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $NewDomain = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Workgroup = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserName = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $Password = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $UserNameNew = '',
    
        [Parameter(Mandatory = $False)]
        [string]
        $PasswordNew = '',
    
        [Parameter(Mandatory = $False)]
        [switch]
        $Restart)
    
    function CreateDomainCred($username, $password) {
        $secureString = ConvertTo-SecureString $password -AsPlainText -Force
        $domainCreds = New-Object System.Management.Automation.PSCredential($username, $secureString)
    
        return $domainCreds
    }
    
    function UnjoinDomain($domain) {
        If ($domain) {
            $unjoinCreds = CreateDomainCred $UserName $Password
            Remove-Computer -UnjoinDomainCredential $unjoinCreds -PassThru -Force
        }
    }
    
    If ($NewDomain) {
        $newDomainCreds = $null
        If ($Domain) {
            UnjoinDomain $Domain
            $newDomainCreds = CreateDomainCred $UserNameNew $PasswordNew
        }
        else {
            $newDomainCreds = CreateDomainCred $UserName $Password
        }
    
        If ($NewComputerName) {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -ComputerName $ComputerName -DomainName $NewDomain -Credential $newDomainCreds -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($Workgroup) {
        UnjoinDomain $Domain
    
        If ($NewComputerName) {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -NewName $NewComputerName -Restart:$Restart
        }
        Else {
            Add-Computer -WorkGroupName $Workgroup -Force -PassThru -Restart:$Restart
        }
    }
    ElseIf ($NewComputerName) {
        If ($Domain) {
            $domainCreds = CreateDomainCred $UserName $Password
            Rename-Computer -NewName $NewComputerName -DomainCredential $domainCreds -Force -PassThru -Restart:$Restart
        }
        Else {
            Rename-Computer -NewName $NewComputerName -Force -PassThru -Restart:$Restart
        }
    }
}


<#

    .SYNOPSIS
        Sets the state of a device to enabled or disabled.

    .DESCRIPTION
        Sets the state of a device to enabled or disabled.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators

#>
function Set-DeviceState {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $ClassGuid,

        [Parameter(Mandatory = $true)]
        [String]
        $DeviceInstancePath,

        [Switch]
        $Enable,

        [Switch]
        $Disable
    )

    if ($Enable -and $Disable) {
        Throw
    } else {
        Add-Type -ErrorAction SilentlyContinue -Language CSharp @"
namespace SME.DeviceManager
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Runtime.ConstrainedExecution;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Text;
    using Microsoft.Win32.SafeHandles;

    [Flags()]
    internal enum Scopes
    {
        Global = 1,
        ConfigSpecific = 2,
        ConfigGeneral = 4
    }

    internal enum DeviceFunction
    {
        SelectDevice = 1,
        InstallDevice = 2,
        AssignResources = 3,
        Properties = 4,
        Remove = 5,
        FirstTimeSetup = 6,
        FoundDevice = 7,
        SelectClassDrivers = 8,
        ValidateClassDrivers = 9,
        InstallClassDrivers = 10,
        CalcDiskSpace = 11,
        DestroyPrivateData = 12,
        ValidateDriver = 13,
        Detect = 15,
        InstallWizard = 16,
        DestroyWizardData = 17,
        PropertyChange = 18,
        EnableClass = 19,
        DetectVerify = 20,
        InstallDeviceFiles = 21,
        UnRemove = 22,
        SelectBestCompatDrv = 23,
        AllowInstall = 24,
        RegisterDevice = 25,
        NewDeviceWizardPreSelect = 26,
        NewDeviceWizardSelect = 27,
        NewDeviceWizardPreAnalyze = 28,
        NewDeviceWizardPostAnalyze = 29,
        NewDeviceWizardFinishInstall = 30,
        Unused1 = 31,
        InstallInterfaces = 32,
        DetectCancel = 33,
        RegisterCoInstallers = 34,
        AddPropertyPageAdvanced = 35,
        AddPropertyPageBasic = 36,
        Reserved1 = 37,
        Troubleshooter = 38,
        PowerMessageWake = 39,
        AddRemotePropertyPageAdvanced = 40,
        UpdateDriverUI = 41,
        Reserved2 = 48
    }

    internal enum DeviceStateAction
    {
        Enable = 1,
        Disable = 2,
        PropChange = 3,
        Start = 4,
        Stop = 5
    }

    [Flags()]
    internal enum SetupDiGetClassDevsFlags
    {
        Default = 1,
        Present = 2,
        AllClasses = 4,
        Profile = 8,
        DeviceInterface = 16
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct DeviceInfoData
    {
        public int Size;
        public Guid ClassGuid;
        public int DevInst;
        public IntPtr Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PropertyChangeParameters
    {
        public int Size;
        public DeviceFunction DeviceFunction;
        public DeviceStateAction StateChange;
        public Scopes Scope;
        public int HwProfile;
    }

    internal static class NativeMethods
    {
        private const string setupApiDll = "setupapi.dll";

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiCallClassInstaller(DeviceFunction installFunction, MySafeHandle deviceInfoSet, [In()]ref DeviceInfoData deviceInfoData);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiEnumDeviceInfo(MySafeHandle deviceInfoSet, int memberIndex, ref DeviceInfoData deviceInfoData);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern MySafeHandle SetupDiGetClassDevs([In()]ref Guid classGuid, [MarshalAs(UnmanagedType.LPWStr)]string enumerator, IntPtr hwndParent, SetupDiGetClassDevsFlags flags);

        [DllImport(setupApiDll, SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiGetDeviceInstanceId(IntPtr DeviceInfoSet, ref DeviceInfoData did, [MarshalAs(UnmanagedType.LPTStr)] StringBuilder DeviceInstanceId, int DeviceInstanceIdSize,out int RequiredSize);

        [DllImport(setupApiDll, CallingConvention = CallingConvention.Winapi, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool SetupDiSetClassInstallParams(MySafeHandle deviceInfoSet, [In()]ref DeviceInfoData deviceInfoData, [In()]ref PropertyChangeParameters classInstallParams, int classInstallParamsSize);
    }

    internal class MySafeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        public MySafeHandle(): base(true)
        {
        }

        protected override bool ReleaseHandle()
        {
            return NativeMethods.SetupDiDestroyDeviceInfoList(this.handle);
        }
    }

    public static class DeviceStateManager
    {
        private const int InvalidIndex = -1;
        private const int ERROR_INSUFFICIENT_BUFFER = 122;
        private const int ERROR_SUCCESS = 0;

        public static int SetDeviceState(Guid classGuid, string instanceId, bool enable)
        {
            MySafeHandle safeHandle = null;
            try
            {
                safeHandle = NativeMethods.SetupDiGetClassDevs(ref classGuid, null, IntPtr.Zero, SetupDiGetClassDevsFlags.Present);
                DeviceInfoData[] diData = GetDeviceInfoData(safeHandle);

                int index = GetDeviceIndex(safeHandle, diData, instanceId);
                if (index == InvalidIndex)
                {
                    return Marshal.GetLastWin32Error();
                }

                return SetDeviceEnabledState(safeHandle, diData[index], enable);
            }
            finally
            {
                if (safeHandle != null)
                {
                    if (safeHandle.IsClosed == false)
                    {
                        safeHandle.Close();
                    }

                    safeHandle.Dispose();
                }
            }
        }

        private static DeviceInfoData[] GetDeviceInfoData(MySafeHandle handle)
        {
            List<DeviceInfoData> data = new List<DeviceInfoData>();
            DeviceInfoData did = new DeviceInfoData();
            int didSize = Marshal.SizeOf(did);
            did.Size = didSize;
            int index = 0;

            while (NativeMethods.SetupDiEnumDeviceInfo(handle, index, ref did))
            {
                data.Add(did);
                index += 1;
                did = new DeviceInfoData();
                did.Size = didSize;
            }

            return data.ToArray();
        }

        private static int GetDeviceIndex(MySafeHandle handle, DeviceInfoData[] diData, string instanceId)
        {
            for (int idx = 0; idx <= diData.Length - 1; idx++)
            {
                StringBuilder sb = new StringBuilder(1);
                int cchRequired = 0;

                bool bRetValue = NativeMethods.SetupDiGetDeviceInstanceId(handle.DangerousGetHandle(), ref diData[idx], sb, sb.Capacity, out cchRequired);
                if (bRetValue == false && Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER)
                {
                    sb.Capacity = cchRequired;
                    bRetValue = NativeMethods.SetupDiGetDeviceInstanceId(handle.DangerousGetHandle(), ref diData[idx], sb, sb.Capacity, out cchRequired);
                }

                if (!bRetValue)
                {
                    return InvalidIndex;
                }

                if (instanceId.Equals(sb.ToString()))
                {
                    return idx;
                }
            }

            return InvalidIndex;
        }

        private static int SetDeviceEnabledState(MySafeHandle handle, DeviceInfoData diData, bool enable)
        {
            PropertyChangeParameters parameters = new PropertyChangeParameters();
            parameters.Size = 8;
            parameters.DeviceFunction = DeviceFunction.PropertyChange;
            parameters.Scope = Scopes.Global;

            parameters.StateChange = enable ? DeviceStateAction.Enable : DeviceStateAction.Disable;

            bool bRetValue = NativeMethods.SetupDiSetClassInstallParams(handle, ref diData, ref parameters, Marshal.SizeOf(parameters));
            if (!bRetValue)
            {
                return Marshal.GetLastWin32Error();
            }

            bRetValue = NativeMethods.SetupDiCallClassInstaller(DeviceFunction.PropertyChange, handle, ref diData);
            if (!bRetValue)
            {
                return Marshal.GetLastWin32Error();
            }

            return ERROR_SUCCESS;
        }
    }
}

"@

        if ($Enable) {
            $enableDevice = $true
        } else {
            $enableDevice = $false
        }

        $guid = [Guid]($ClassGuid)
        [SME.DeviceManager.DeviceStateManager]::SetDeviceState($guid, $DeviceInstancePath, $enableDevice)
    }

}


<#
    .SYNOPSIS
        Sets configuration of the specified network interface to use DHCP and updates DNS settings.
    
    .DESCRIPTION
        Sets configuration of the specified network interface to use DHCP and updates DNS settings.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
#>
function Set-DhcpIP {
    param (
        [Parameter(Mandatory = $true)]
        [string] $interfaceIndex,

        [Parameter(Mandatory = $true)]
        [string] $addressFamily,

        [string] $preferredDNS,

        [string] $alternateDNS
    )
    
    Import-Module NetTCPIP
    
    $ErrorActionPreference = 'Stop'
    
    $ipInterface = Get-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily
    $netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -ErrorAction SilentlyContinue
    if ($addressFamily -eq "IPv4") {
        $prefix = '0.0.0.0/0'
    }
    else {
        $prefix = '::/0'
    }
    
    $netRoute = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue
    
    # avoid extra work if dhcp already set up
    if ($ipInterface.Dhcp -eq 'Disabled') {
        if ($netIPAddress) {
            $netIPAddress | Remove-NetIPAddress -Confirm:$false
        }
        if ($netRoute) {
            $netRoute | Remove-NetRoute -Confirm:$false
        }
    
        $ipInterface | Set-NetIPInterface -DHCP Enabled
    }
    
    # reset or configure dns servers
    $interfaceAlias = $ipInterface.InterfaceAlias
    if ($preferredDNS) {
        netsh.exe interface $addressFamily set dnsservers name="$interfaceAlias" source=static validate=yes address="$preferredDNS"
        if (($LASTEXITCODE -eq 0) -and $alternateDNS) {
            netsh.exe interface $addressFamily add dnsservers name="$interfaceAlias" validate=yes address="$alternateDNS"
        }
    }
    else {
        netsh.exe interface $addressFamily delete dnsservers name="$interfaceAlias" address=all
    }
    
    # captures exit code of netsh.exe
    $LASTEXITCODE
    
}


<#
    
    .SYNOPSIS
        Updates or renames an environment variable specified by name, type, data and previous data.
    
    .DESCRIPTION
        Updates or Renames an environment variable specified by name, type, data and previrous data.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-EnvironmentVariable {
    param(
        [Parameter(Mandatory = $True)]
        [String]
        $oldName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $newName,
    
        [Parameter(Mandatory = $True)]
        [String]
        $value,
    
        [Parameter(Mandatory = $True)]
        [String]
        $type
    )
    
    Set-StrictMode -Version 5.0
    
    $nameChange = $false
    if ($newName -ne $oldName) {
        $nameChange = $true
    }
    
    If (-not [Environment]::GetEnvironmentVariable($oldName, $type)) {
        @{ Status = "currentMissing" }
        return
    }
    
    If ($nameChange -and [Environment]::GetEnvironmentVariable($newName, $type)) {
        @{ Status = "targetConflict" }
        return
    }
    
    If ($nameChange) {
        [Environment]::SetEnvironmentVariable($oldName, $null, $type)
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }
    Else {
        [Environment]::SetEnvironmentVariable($newName, $value, $type)
        @{ Status = "success" }
    }    
}


<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host Enhanced Session Mode settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host Enhanced Session Mode settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVEnhancedSessionModeSettings {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $enableEnhancedSessionMode
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    # Create arguments
    $args = @{'EnableEnhancedSessionMode' = $enableEnhancedSessionMode};
    
    Set-VMHost @args
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        EnableEnhancedSessionMode
    
}


<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host General settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host General settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVHostGeneralSettings {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $virtualHardDiskPath,
        [Parameter(Mandatory = $true)]
        [String]
        $virtualMachinePath
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    # Create arguments
    $args = @{'VirtualHardDiskPath' = $virtualHardDiskPath};
    $args += @{'VirtualMachinePath' = $virtualMachinePath};
    
    Set-VMHost @args
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        VirtualHardDiskPath, `
        VirtualMachinePath
    
}


<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host Live Migration settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host Live Migration settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVHostLiveMigrationSettings {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $virtualMachineMigrationEnabled,
        [Parameter(Mandatory = $true)]
        [int]
        $maximumVirtualMachineMigrations,
        [Parameter(Mandatory = $true)]
        [int]
        $virtualMachineMigrationPerformanceOption,
        [Parameter(Mandatory = $true)]
        [int]
        $virtualMachineMigrationAuthenticationType
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    if ($virtualMachineMigrationEnabled) {
        $isServer2012 = [Environment]::OSVersion.Version.Major -eq 6 -and [Environment]::OSVersion.Version.Minor -eq 2;
        
        Enable-VMMigration;
    
        # Create arguments
        $args = @{'MaximumVirtualMachineMigrations' = $maximumVirtualMachineMigrations};
        $args += @{'VirtualMachineMigrationAuthenticationType' = $virtualMachineMigrationAuthenticationType; };
    
        if (!$isServer2012) {
            $args += @{'VirtualMachineMigrationPerformanceOption' = $virtualMachineMigrationPerformanceOption; };
        }
    
        Set-VMHost @args;
    } else {
        Disable-VMMigration;
    }
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        maximumVirtualMachineMigrations, `
        VirtualMachineMigrationAuthenticationType, `
        VirtualMachineMigrationEnabled, `
        VirtualMachineMigrationPerformanceOption
    
}


<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVHostNumaSpanningSettings {
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $numaSpanningEnabled
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    # Create arguments
    $args = @{'NumaSpanningEnabled' = $numaSpanningEnabled};
    
    Set-VMHost @args
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        NumaSpanningEnabled
    
}


<#
    
    .SYNOPSIS
        Sets a computer's Hyper-V Host Storage Migration settings.
    
    .DESCRIPTION
        Sets a computer's Hyper-V Host Storage Migrtion settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Hyper-V-Administrators
    
#>
function Set-HyperVHostStorageMigrationSettings {
    param (
        [Parameter(Mandatory = $true)]
        [int]
        $maximumStorageMigrations
        )
    
    Set-StrictMode -Version 5.0
    Import-Module Hyper-V
    
    # Create arguments
    $args = @{'MaximumStorageMigrations' = $maximumStorageMigrations; };
    
    Set-VMHost @args
    
    Get-VMHost | Microsoft.PowerShell.Utility\Select-Object `
        MaximumStorageMigrations
    
}


<#
    
    .SYNOPSIS
        Set local group properties.
    
    .DESCRIPTION
        Set local group properties. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-LocalGroupProperties {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $GroupName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Description
    )
    
    try {
        $group = [ADSI]("WinNT://localhost/$GroupName, group")
        if ($Description -ne $null) { $group.Description = $Description }
        $group.SetInfo()
    }
    catch [System.Management.Automation.RuntimeException]
    {
            Write-Error $_.Exception.Message
    }
    
    return $true
    
}


<#
    
    .SYNOPSIS
        Set local user password.
    
    .DESCRIPTION
        Set local user password. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-LocalUserPassword {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Password
    )
    
    if (-not $Password)
    {
        $Password = ""
    }
    $user = [ADSI]("WinNT://localhost/$UserName, user")
    $change = $user.psbase.invoke("SetPassword", "$Password")
}


<#
    
    .SYNOPSIS
        Set local user properties.
    
    .DESCRIPTION
        Set local user properties. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-LocalUserProperties {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $UserName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $FullName,
    
        [Parameter(Mandatory = $false)]
        [String]
        $Description
    )
    
    $user = [ADSI]("WinNT://localhost/$UserName, user")
    if ($Description -ne $null) { $user.Description = $Description }
    if ($FullName -ne $null) { $user.FullName = $FullName }
    $user.SetInfo()
    
    return $true
    
}


<#
    
    .SYNOPSIS
        Creates new value based on the selected key.
    
    .DESCRIPTION
        Creates new value based on the selected key. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-RegistryValue {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$name,
        [Parameter(Mandatory = $true)]
        [String]$value,
        [Parameter(Mandatory = $true) ]
        [int]$valueType,
        [Parameter(Mandatory = $false)]
        [byte[]]$valueBytes             
        )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()       
    if ($valueType -eq 3){
        Set-ItemProperty -Path $path -Name $name -Value $valueBytes 
    }
    else{
        Set-ItemProperty -Path $path -Name $name -Value $value 
    }       
}


<#
    
    .SYNOPSIS
        Sets a computer's remote desktop settings.
    
    .DESCRIPTION
        Sets a computer's remote desktop settings.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-RemoteDesktop {
    param(
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktop,
        
        [Parameter(Mandatory = $False)]
        [boolean]
        $AllowRemoteDesktopWithNLA,
        
        [Parameter(Mandatory=$False)]
        [boolean]
        $EnableRemoteApp)
    
    Import-Module NetSecurity
    Import-Module Microsoft.PowerShell.Management
        
    $regKey1 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
    $regKey2 = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
    
    $keyProperty1 = "fDenyTSConnections"
    $keyProperty2 = "UserAuthentication"
    $keyProperty3 = "EnableRemoteApp"
    
    $keyPropertyValue1 = $(if ($AllowRemoteDesktop -eq $True) { 0 } else { 1 })
    $keyPropertyValue2 = $(if ($AllowRemoteDesktopWithNLA -eq $True) { 1 } else { 0 })
    $keyPropertyValue3 = $(if ($EnableRemoteApp -eq $True) { 1 } else { 0 })
    
    if (!(Test-Path $regKey1)) {
        New-Item -Path $regKey1 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey1 -Name $keyProperty1 -Value $keyPropertyValue1 -PropertyType DWORD -Force | Out-Null
    New-ItemProperty -Path $regKey1 -Name $keyProperty3 -Value $keyPropertyValue3 -PropertyType DWORD -Force | Out-Null
    
    if (!(Test-Path $regKey2)) {
        New-Item -Path $regKey2 -Force | Out-Null
    }
    
    New-ItemProperty -Path $regKey2 -Name $keyProperty2 -Value $keyPropertyValue2 -PropertyType DWORD -Force | Out-Null
    
    Enable-NetFirewallRule -DisplayGroup 'Remote Desktop'
}


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


<#
    
    .SYNOPSIS
        Sets the current log on user for the specified service.
    
    .DESCRIPTION
        Sets the current log on user for the specified service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ServiceLogOnUser {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName,
        [string] $username,
        [string] $password
    )
    
    if ($username -and $password) {
        Invoke-Expression "$($env:SystemDrive)\Windows\System32\sc.exe config $($serviceName) obj= `"$($username)`" password= $($password)" > $null
    }
    else {
        Invoke-Expression "$($env:SystemDrive)\Windows\System32\sc.exe config $($serviceName) obj= LocalSystem" > $null
    }
    
    $result = New-Object PSObject
    $result | Add-Member -MemberType NoteProperty -Name 'ExitCode' -Value $LASTEXITCODE
    $exceptionObject = [ComponentModel.Win32Exception]$LASTEXITCODE
    if ($exceptionObject) {
        $result | Add-Member -MemberType NoteProperty -Name 'ErrorMessage' -Value $exceptionObject.message
    }
    
    $result
    
}


<#
    
    .SYNOPSIS
        Sets the recovery options for a specific service.
    
    .DESCRIPTION
        Sets the recovery options for a specific service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ServiceRecoveryOptions {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName,
        [string] $firstFailureAction,
        [string] $secondFailureAction,
        [string] $thirdFailureAction,
        [Parameter(Mandatory = $true)] [int] $resetFailCountDays,
        [int] $restartServiceMinutes,
        [string] $pathToProgram,
        [string] $programParameters
    )
    
    $resetIntervalSeconds = $resetFailCountDays * 24 * 60 * 60
    $defaultIntervalMilliseconds = 60000
    $restartIntervalMilliseconds = $defaultIntervalMilliseconds
    
    if ($restartServiceMinutes) {
      $restartIntervalMilliseconds = $restartServiceMinutes * 60 * 1000
    }
    
    $firstFailureActionInterval = $defaultIntervalMilliseconds
    if ($firstFailureAction -eq 'restart') {
      $firstFailureActionInterval = $restartIntervalMilliseconds
    }
    
    $secondsFailureActionInterval = $defaultIntervalMilliseconds
    if ($secondFailureAction -eq 'restart') {
      $secondsFailureActionInterval = $restartIntervalMilliseconds
    }
    
    $thirdFailureActionInterval = $defaultIntervalMilliseconds
    if ($thirdFailureAction -eq 'restart') {
      $thirdFailureActionInterval = $restartIntervalMilliseconds
    }
    
    $actionsString = "$($firstFailureAction)/$($firstFailureActionInterval)/$($secondFailureAction)/$($secondsFailureActionInterval)/$($thirdFailureAction)/$($thirdFailureActionInterval)"
    
    
    Invoke-Expression "$($env:SystemDrive)\Windows\System32\sc.exe failure $($serviceName) reset= $($resetIntervalSeconds) actions= $($actionsString)" > $null
    
    
    if ($pathToProgram -ne $null) {
      $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
      # store path as "C:/Path/To Program" to be consistent with behavior in native services app
      Set-ItemProperty -Path $regPath -Name FailureCommand -Value "`"$($pathToProgram)`" $($programParameters)"
    }
    
    $result = New-Object PSObject
    $result | Add-Member -MemberType NoteProperty -Name 'ExitCode' -Value $LASTEXITCODE
    $exceptionObject = [ComponentModel.Win32Exception]$LASTEXITCODE
    if ($exceptionObject) {
      $result | Add-Member -MemberType NoteProperty -Name 'ErrorMessage' -Value $exceptionObject.message
    }
    
    $result
    
}


<#
    
    .SYNOPSIS
        Sets the startup type, path and parameters for the specified service.
    
    .DESCRIPTION
        Sets the startup type, path and parameters for the specified service.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Set-ServiceStartOptions {
    param (
        [Parameter(Mandatory = $true)] [string] $serviceName,
        [string] $path,
        [string] $startupType
    )
    
    
    if ($startupType) {
        $service = Get-WmiObject -class Win32_Service -namespace root\cimv2 | Where-Object { $_.Name -eq $serviceName }
        if ($service) {
            $startupResult = $service.ChangeStartMode($startupType)
            if ($startupResult -and $startupResult.ReturnValue -ne 0) {
                return $startupResult.ReturnValue
            }
        }
        else {
            # unexpected error
            return -1
        }
    }
    
    if ($path) {
        $regPath = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$($serviceName)"
        Set-ItemProperty -Path $regPath -Name ImagePath -Value $path
    }
    
    # if we get here the script was successful, return 0 for success
    return 0
    
}


<#
    
    .SYNOPSIS
        Sets configuration of the specified network interface to use a static IP address and updates DNS settings.
    
    .DESCRIPTION
        Sets configuration of the specified network interface to use a static IP address and updates DNS settings. The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Administrators
    
#>
function Set-StaticIP {
    param (
        [Parameter(Mandatory = $true)] [string] $interfaceIndex,
        [Parameter(Mandatory = $true)] [string] $ipAddress,
        [Parameter(Mandatory = $true)] [string] $prefixLength,
        [string] $defaultGateway,
        [string] $preferredDNS,
        [string] $alternateDNS,
        [Parameter(Mandatory = $true)] [string] $addressFamily
    )
    
    Import-Module NetTCPIP
    
    Set-StrictMode -Version 5.0
    $ErrorActionPreference = 'Stop'
    
    $netIPAddress = Get-NetIPAddress -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -ErrorAction SilentlyContinue
    
    if ($addressFamily -eq "IPv4") {
        $prefix = '0.0.0.0/0'
    }
    else {
        $prefix = '::/0'
    }
    
    $netRoute = Get-NetRoute -InterfaceIndex $interfaceIndex -DestinationPrefix $prefix -ErrorAction SilentlyContinue
    
    if ($netIPAddress) {
        $netIPAddress | Remove-NetIPAddress -Confirm:$false
    }
    if ($netRoute) {
        $netRoute | Remove-NetRoute -Confirm:$false
    }
    
    Set-NetIPInterface -InterfaceIndex $interfaceIndex -AddressFamily $addressFamily -DHCP Disabled
    
    try {
        # this will fail if input is invalid
        if ($defaultGateway) {
            $netIPAddress | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -DefaultGateway $defaultGateway -AddressFamily $addressFamily -ErrorAction Stop
        }
        else {
            $netIPAddress | New-NetIPAddress -IPAddress $ipAddress -PrefixLength $prefixLength -AddressFamily $addressFamily -ErrorAction Stop
        }
    }
    catch {
        # restore net route and ip address to previous values
        if ($netRoute -and $netIPAddress) {
            $netIPAddress | New-NetIPAddress -DefaultGateway $netRoute.NextHop -PrefixLength $netIPAddress.PrefixLength
        }
        elseif ($netIPAddress) {
            $netIPAddress | New-NetIPAddress
        }
        throw
    }
    
    $interfaceAlias = $netIPAddress.InterfaceAlias
    if ($preferredDNS) {
        netsh.exe interface $addressFamily set dnsservers name="$interfaceAlias" source=static validate=yes address="$preferredDNS"
        if (($LASTEXITCODE -eq 0) -and $alternateDNS) {
            netsh.exe interface $addressFamily add dnsservers name="$interfaceAlias" validate=yes address="$alternateDNS"
        }
        return $LASTEXITCODE
    }
    else {
        return 0
    }    
}


<#
    
    .SYNOPSIS
        Sets the disk offline.
    
    .DESCRIPTION
        Sets the disk offline.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER diskNumber
        The disk number.
    
    .PARAMETER isOffline
        True to set the disk offline.

#>
function Set-StorageDiskOffline {
    param (
        [UInt32]
        $diskNumber,
        [Boolean]
        $isOffline = $true
    )
    
    Import-Module Storage
    
    Set-Disk -Number $diskNumber -IsOffline $isOffline
}


<#
    
    .SYNOPSIS
        Starts new process.
    
    .DESCRIPTION
        Starts new process.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-CimProcess {
    Param(
    [string]$CommandLine
    )
    
    import-module CimCmdlets
    
    Invoke-CimMethod -Namespace root/Microsoft/Windows/ManagementTools -ClassName MSFT_MTProcess -MethodName CreateProcess -Arguments @{CommandLine=$CommandLine;}
    
}


<#
    
    .SYNOPSIS
        Start a service using CIM Win32_Service class.
    
    .DESCRIPTION
        Start a service using CIM Win32_Service class.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-CimService {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName StartService
    
}


<#
    
    .SYNOPSIS
        Start Disk Performance monitoring.
    
    .DESCRIPTION
        Start Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 3
    & diskperf -Y
}


<#
    
    .SYNOPSIS
        Start a new process on downlevel computer.
    
    .DESCRIPTION
        Start a new process on downlevel computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-ProcessDownlevel {
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $commandLine
    )
    
    Set-StrictMode -Version 5.0
    
    Start-Process $commandLine
    
}


<#
    
    .SYNOPSIS
        Script to start a scheduled tasks.
    
    .DESCRIPTION
        Script to start a scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Start-ScheduledTask {
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $true)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName | ScheduledTasks\Start-ScheduledTask 
}


<#
    
    .SYNOPSIS
        Shutdown Windows Operating System by using Win32_OperatingSystem provider.
    
    .DESCRIPTION
        Shutdown Windows Operating System by using Win32_OperatingSystem provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-CimOperatingSystem {
    Param(
    )
    
    import-module CimCmdlets
    
    Invoke-CimMethod -Namespace root/cimv2 -ClassName Win32_OperatingSystem -MethodName Shutdown
    
}


<#
    
    .SYNOPSIS
        Stop a process.
    
    .DESCRIPTION
        Stop a process.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-CimProcess {
    Param(
    [System.UInt16]$ProcessId
    )
    
    import-module CimCmdlets
    
    $instance = New-CimInstance -Namespace root/Microsoft/Windows/ManagementTools -ClassName MSFT_MTProcess -Key @('ProcessId') -Property @{ProcessId=$ProcessId;} -ClientOnly
    Remove-CimInstance $instance
    
}


<#
    
    .SYNOPSIS
        Stop Disk Performance monitoring.
    
    .DESCRIPTION
        Stop Disk Performance monitoring.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-DiskPerf {
    # Update the registry key at HKLM:SYSTEM\\CurrentControlSet\\Services\\Partmgr
    #   EnableCounterForIoctl = DWORD 1
    & diskperf -N
}


<#
    
    .SYNOPSIS
        Stop the process on a computer.
    
    .DESCRIPTION
        Stop the process on a computer.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-Processes {
    param
    (
        [Parameter(Mandatory = $true)]
        [int[]]
        $processIds
    )
    
    Set-StrictMode -Version 5.0
    
    Stop-Process $processIds -Force
}


<#
    
    .SYNOPSIS
        Script to stop a scheduled tasks.
    
    .DESCRIPTION
        Script to stop a scheduled tasks.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-ScheduledTask {
    param (
      [Parameter(Mandatory = $true)]
      [String]
      $taskPath,
    
      [Parameter(Mandatory = $true)]
      [String]
      $taskName
    )
    
    Import-Module ScheduledTasks
    
    Get-ScheduledTask -TaskPath $taskPath -TaskName $taskName | ScheduledTasks\Stop-ScheduledTask
}


<#
    
    .SYNOPSIS
        Stop a service using Stop-Service cmdlet.
    
    .DESCRIPTION
        Stop a service using Stop-Service cmdlet.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Stop-ServiceByName {
    Param(
    [string]$Name
    )
    
    Stop-Service -Name $Name -Force
}


<#
    
    .SYNOPSIS
        Suspend a service using CIM Win32_Service class.
    
    .DESCRIPTION
        Suspend a service using CIM Win32_Service class.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Suspend-CimService {
    Param(
    [string]$Name
    )
    
    import-module CimCmdlets
    
    $keyInstance = New-CimInstance -Namespace root/cimv2 -ClassName Win32_Service -Key @('Name') -Property @{Name=$Name;} -ClientOnly
    Invoke-CimMethod $keyInstance -MethodName PauseService
    
}


<#
    
    .SYNOPSIS
        Checks if a file or folder exists
    
    .DESCRIPTION
        Checks if a file or folder exists
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
    Administrators
    
    .PARAMETER Path
        String -- The path to check if it exists
    
#>
function Test-FileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path    
    )
    
    Set-StrictMode -Version 5.0
    
    Test-Path -path $Path
    
}


<#
    
    .SYNOPSIS
        Tests if a registry value exists.
    
    .DESCRIPTION
        The usual ways for checking if a registry value exists don't handle when a value simply has an
        empty or null value.  This function actually checks if a key has a value with a given name.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .EXAMPLE
        Test-RegistryKeyValue -Path 'hklm:\Software\Carbon\Test' -Name 'Title'
        Returns `True` if `hklm:\Software\Carbon\Test` contains a value named 'Title'.  `False` otherwise.
    
    .ROLE
        Administrators
    
#>
function Test-RegistryValueExists {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]
        # The path to the registry key where the value should be set.  Will be created if it doesn't exist.
        $Path,
    
        [Parameter(Mandatory=$true)]
        [string]
        # The name of the value being set.
        $Name
    )
    
    $ErrorActionPreference = "Stop"
    
    $Error.Clear()   
    if( -not (Test-Path -Path $Path -PathType Container) )
    {
        return $false
    }
    
    $properties = Get-ItemProperty -Path $Path 
    if( -not $properties )
    {
        return $false
    }
    
    $member = Get-Member -InputObject $properties -Name $Name
    if( $member )
    {
        return $true
    }
    else
    {
        return $false
    }
    
}


<#
    .SYNOPSIS
        UnInstalls a Feature/Role/Role Service on the target server.
    
    .DESCRIPTION
        UnInstalls a Feature/Role/Role Service on the target server, using UnInstall-WindowsFeature PowerShell cmdlet.
        Returns a status object that contains the following properties:
            success - true/false depending on if the overall operation Succeeded
            status - status message
            result - response from UnInstall-WindowsFeature call

        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER FeatureName
        Is a required parameter and is the name of the Role/Feature/Role Service to un-install
    
    .PARAMETER IncludeManagementTools
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .PARAMETER Restart
        Is an optional switch parameter that is passed as a similar named parameter to Install-WindowsFeature
    
    .EXAMPLE
        # Un-Installs the feature 'ManagementObject'
        Uninstall-RolesAndFeatures -FeatureName 'ManagementOData'
    
    
    .EXAMPLE
        # Un-Installs the role 'Web-Server' and management tools
        Uninstall-RolesAndFeatures -FeatureName 'Web-Server' -IncludeManagementTools
    
    .EXAMPLE
        # Un-Installs the feature 'ManagementObject' without management tools and reboots the server
        Uninstall-RolesAndFeatures -FeatureName 'ManagementOData' -Restart
    
    .ROLE
        Administrators
    
#>
function Uninstall-RolesAndFeatures {
    param(
        [Parameter(Mandatory=$True)]
        [string[]]
        $FeatureName,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $IncludeManagementTools,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $Restart,
    
        [Parameter(Mandatory=$False)]
        [Switch]
        $WhatIf
    )
    
    Import-Module ServerManager
    
    Enum UnInstallStatus {
        Failed = 0
        Succeeded = 1
        NoSuchFeature = 2
        NotInstalled = 3
        Pending = 4
    }
    
    $result  = $Null
    $status = $Null
    $success = $False
    
    $ErrorActionPreference = "Stop"
    
    $feature = Get-WindowsFeature -Name $FeatureName
    If ($feature) {
        If ($feature.Where({$_.InstallState -eq 'Installed'})) {
            Try {
                $result = UnInstall-WindowsFeature -Name $FeatureName -IncludeManagementTools:$IncludeManagementTools -Restart:$Restart -WhatIf:$WhatIf
                $success = $result -AND $result.Success
                $status = if ($success) { [UnInstallStatus]::Succeeded } Else { [UnInstallStatus]::Failed }
            }
            Catch {
                If ($success -AND $Restart -AND $result.restartNeeded -eq 'Yes') {
                    $status = [UnInstallStatus]::Pending
                    $error.clear()
                } Else {
                    Throw
                }
            }
        } Else {
            $success = $True
            $status = [UnInstallStatus]::NotInstalled
        }
    } Else {
        $success = $False
        $status = [UnInstallStatus]::NoSuchFeature
    }
    
    @{ 'success' = $success ; 'status' = $status ; 'result' = $result }
    
}


<#
    
    .SYNOPSIS
        Renew Certificate
    
    .DESCRIPTION
        Renew Certificate

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Update-Certificate {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $username,
        [Parameter(Mandatory = $true)]
        [String]
        $password,
        [Parameter(Mandatory = $true)]
        [Boolean]
        $sameKey,
        [Parameter(Mandatory = $true)]
        [Boolean]
        $isRenew,
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
        [Parameter(Mandatory = $true)]
        [String]
        $RemoteComputer
    )
    
    $pw = ConvertTo-SecureString $password -AsPlainText -Force
    $credential = New-Object PSCredential($username, $pw)
    
    Invoke-Command -Computername $RemoteComputer -ScriptBlock {
        param($Path, $isRenew, $sameKey)
        $global:result = ""
    
        $Cert = Get-Item -Path $Path
    
        $Template = $Cert.Extensions | Where-Object {$_.Oid.FriendlyName -match "Template"}
        if (!$Template) {
            $global:result = "NoTemplate"
            $global:result
            exit
        }
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379399(v=vs.85).aspx
        #X509CertificateEnrollmentContext
        $ContextUser                      = 0x1
        $ContextMachine                   = 0x2
        $ContextAdministratorForceMachine = 0x3
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374936(v=vs.85).aspx
        #EncodingType
        $XCN_CRYPT_STRING_BASE64HEADER        = 0
        $XCN_CRYPT_STRING_BASE64              = 0x1
        $XCN_CRYPT_STRING_BINARY              = 0x2
        $XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3
        $XCN_CRYPT_STRING_HEX                 = 0x4
        $XCN_CRYPT_STRING_HEXASCII            = 0x5
        $XCN_CRYPT_STRING_BASE64_ANY          = 0x6
        $XCN_CRYPT_STRING_ANY                 = 0x7
        $XCN_CRYPT_STRING_HEX_ANY             = 0x8
        $XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9
        $XCN_CRYPT_STRING_HEXADDR             = 0xa
        $XCN_CRYPT_STRING_HEXASCIIADDR        = 0xb
        $XCN_CRYPT_STRING_HEXRAW              = 0xc
        $XCN_CRYPT_STRING_NOCRLF              = 0x40000000
        $XCN_CRYPT_STRING_NOCR                = 0x80000000
    
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa379430(v=vs.85).aspx
        #X509RequestInheritOptions
        $InheritDefault                = 0x00000000
        $InheritNewDefaultKey          = 0x00000001
        $InheritNewSimilarKey          = 0x00000002
        $InheritPrivateKey             = 0x00000003
        $InheritPublicKey              = 0x00000004
        $InheritKeyMask                = 0x0000000f
        $InheritNone                   = 0x00000010
        $InheritRenewalCertificateFlag = 0x00000020
        $InheritTemplateFlag           = 0x00000040
        $InheritSubjectFlag            = 0x00000080
        $InheritExtensionsFlag         = 0x00000100
        $InheritSubjectAltNameFlag     = 0x00000200
        $InheritValidityPeriodFlag     = 0x00000400
        $X509RequestInheritOptions = $InheritTemplateFlag
        if ($isRenew) {
            $X509RequestInheritOptions += $InheritRenewalCertificateFlag
        }
        if ($sameKey) {
            $X509RequestInheritOptions += $InheritPrivateKey
        }
    
        $Context = $ContextAdministratorForceMachine
    
        $PKCS10 = New-Object -ComObject X509Enrollment.CX509CertificateRequestPkcs10
        $PKCS10.Silent=$true
    
        $PKCS10.InitializeFromCertificate($Context,[System.Convert]::ToBase64String($Cert.RawData), $XCN_CRYPT_STRING_BASE64, $X509RequestInheritOptions)
        $PKCS10.AlternateSignatureAlgorithm=$false
        $PKCS10.SmimeCapabilities=$false
        $PKCS10.SuppressDefaults=$true
        $PKCS10.Encode()
        #https://msdn.microsoft.com/en-us/library/windows/desktop/aa377809(v=vs.85).aspx
        $Enroll = New-Object -ComObject X509Enrollment.CX509Enrollment
        $Enroll.InitializeFromRequest($PKCS10)
        $Enroll.Enroll()
    
        if ($Error.Count -eq 0) {
            $Cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2
            $Cert.Import([System.Convert]::FromBase64String($Enroll.Certificate(1)))
            $global:result = $Cert.Thumbprint
        }
    
        $global:result
    
    } -Credential $credential -ArgumentList $Path, $isRenew, $sameKey
    
}


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


<#
   
    .SYNOPSIS
        Update a new Quota for volume.
   
    .DESCRIPTION
        Update a new Quota for volume.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
   
    .ROLE
        Administrators
   
    .PARAMETER disabledQuota
        Enable or disable quota.
   
    .PARAMETER path
        Path of the quota.
   
    .PARAMETER size
        The size of quota.
   
    .PARAMETER softLimit
        Deny if usage exceeding quota limit.
   
#>
function Update-StorageQuota {
   param
   (
       # Enable or disable quota.
       [Parameter(Mandatory = $true)]
       [Boolean]
       $disabledQuota,
   
       # Path of the quota.
       [Parameter(Mandatory = $true)]
       [String]
       $path,
   
       # The size of quota.
       [Parameter(Mandatory = $true)]
       [String]
       $size,
   
       # Deny if usage exceeding quota limit.
       [Parameter(Mandatory = $true)]
       [Boolean]
       $softLimit
   )
   Import-Module FileServerResourceManager
   
   $scriptArguments = @{
       Path = $path
       Disabled = $disabledQuota
       SoftLimit = $softLimit
   }
   
   if ($size) {
       $scriptArguments.Size = $size
   }
   
   Set-FsrmQuota @scriptArguments
   
}


[System.Collections.ArrayList]$script:FunctionsForSBUse = @(
    ${Function:GetElevation}.Ast.Extent.Text
    ${Function:Add-FolderShare}.Ast.Extent.Text
    ${Function:Add-FolderShareNameUser}.Ast.Extent.Text
    ${Function:Add-FolderShareUser}.Ast.Extent.Text
    ${Function:Add-ScheduledTaskAction}.Ast.Extent.Text
    ${Function:Add-ScheduledTaskTrigger}.Ast.Extent.Text
    ${Function:Add-UserToLocalGroups}.Ast.Extent.Text
    ${Function:Clear-EventLogChannel}.Ast.Extent.Text
    ${Function:Clear-LogChannelAfterExport}.Ast.Extent.Text
    ${Function:Compress-ArchiveFileSystemEntity}.Ast.Extent.Text
    ${Function:Disable-CimPnpEntity}.Ast.Extent.Text
    ${Function:Disable-FirewallRule}.Ast.Extent.Text
    ${Function:Disable-ScheduledTask}.Ast.Extent.Text
    ${Function:Dismount-StorageVHD}.Ast.Extent.Text
    ${Function:Edit-FirewallRule}.Ast.Extent.Text
    ${Function:Edit-FolderShareInheritanceFlag}.Ast.Extent.Text
    ${Function:Edit-FolderShareUser}.Ast.Extent.Text
    ${Function:Edit-StorageVolume}.Ast.Extent.Text
    ${Function:Enable-CimPnpEntity}.Ast.Extent.Text
    ${Function:Enable-FirewallRule}.Ast.Extent.Text
    ${Function:Enable-ScheduledTask}.Ast.Extent.Text
    ${Function:Expand-ArchiveFileSystemEntity}.Ast.Extent.Text
    ${Function:Export-Certificate}.Ast.Extent.Text
    ${Function:Export-EventLogChannel}.Ast.Extent.Text
    ${Function:Export-RegistryContent}.Ast.Extent.Text
    ${Function:Find-DeviceDrivers}.Ast.Extent.Text
    ${Function:Find-WindowsUpdateList}.Ast.Extent.Text
    ${Function:Format-StorageVolume}.Ast.Extent.Text
    ${Function:Get-AntiMalwareSoftwareStatus}.Ast.Extent.Text
    ${Function:Get-AutomaticUpdatesOptions}.Ast.Extent.Text
    ${Function:Get-CertificateOverview}.Ast.Extent.Text
    ${Function:Get-Certificates}.Ast.Extent.Text
    ${Function:Get-CertificateScopes}.Ast.Extent.Text
    ${Function:Get-CertificateStores}.Ast.Extent.Text
    ${Function:Get-CertificateTreeNodes}.Ast.Extent.Text
    ${Function:Get-CimClassPnpEntity}.Ast.Extent.Text
    ${Function:Get-CimEventLogRecords}.Ast.Extent.Text
    ${Function:Get-CimMemorySummary}.Ast.Extent.Text
    ${Function:Get-CimNamespaceWithinMocrosoftWindows}.Ast.Extent.Text
    ${Function:Get-CimNetworkAdapterSummary}.Ast.Extent.Text
    ${Function:Get-CimPnpEntity}.Ast.Extent.Text
    ${Function:Get-CimPnpEntityDeviceProperties}.Ast.Extent.Text
    ${Function:Get-CimPnpEntityForDevice}.Ast.Extent.Text
    ${Function:Get-CimPnpSignedDriver}.Ast.Extent.Text
    ${Function:Get-CimProcess}.Ast.Extent.Text
    ${Function:Get-CimProcessorSummary}.Ast.Extent.Text
    ${Function:Get-CimRegistrySubKeys}.Ast.Extent.Text
    ${Function:Get-CimRegistryValues}.Ast.Extent.Text
    ${Function:Get-CimServiceDetail}.Ast.Extent.Text
    ${Function:Get-CimSingleService}.Ast.Extent.Text
    ${Function:Get-CimWin32ComputerSystem}.Ast.Extent.Text
    ${Function:Get-CimWin32LogicalDisk}.Ast.Extent.Text
    ${Function:Get-CimWin32NetworkAdapter}.Ast.Extent.Text
    ${Function:Get-CimWin32OperatingSystem}.Ast.Extent.Text
    ${Function:Get-CimWin32PhysicalMemory}.Ast.Extent.Text
    ${Function:Get-CimWin32Processor}.Ast.Extent.Text
    ${Function:Get-ClientConnectionStatus}.Ast.Extent.Text
    ${Function:Get-ClusterInventory}.Ast.Extent.Text
    ${Function:Get-ClusterNodes}.Ast.Extent.Text
    ${Function:Get-ComputerIdentification}.Ast.Extent.Text
    ${Function:Get-ComputerName}.Ast.Extent.Text
    ${Function:Get-DeviceDriverInformation}.Ast.Extent.Text
    ${Function:Get-DiskSummary}.Ast.Extent.Text
    ${Function:Get-DiskSummaryDownlevel}.Ast.Extent.Text
    ${Function:Get-EnvironmentVariables}.Ast.Extent.Text
    ${Function:Get-EventLogChannelStatus}.Ast.Extent.Text
    ${Function:Get-EventLogFilteredCount}.Ast.Extent.Text
    ${Function:Get-EventLogRecords}.Ast.Extent.Text
    ${Function:Get-EventLogSummary}.Ast.Extent.Text
    ${Function:Get-FileNamesInPath}.Ast.Extent.Text
    ${Function:Get-FileSystemEntities}.Ast.Extent.Text
    ${Function:Get-FileSystemRoot}.Ast.Extent.Text
    ${Function:Get-FirewallProfile}.Ast.Extent.Text
    ${Function:Get-FirewallRules}.Ast.Extent.Text
    ${Function:Get-FolderItemCount}.Ast.Extent.Text
    ${Function:Get-FolderOwner}.Ast.Extent.Text
    ${Function:Get-FolderShareNames}.Ast.Extent.Text
    ${Function:Get-FolderShareNameUserAccess}.Ast.Extent.Text
    ${Function:Get-FolderShareStatus}.Ast.Extent.Text
    ${Function:Get-FolderShareUsers}.Ast.Extent.Text
    ${Function:Get-HyperVEnhancedSessionModeSettings}.Ast.Extent.Text
    ${Function:Get-HyperVGeneralSettings}.Ast.Extent.Text
    ${Function:Get-HyperVHostPhysicalGpuSettings}.Ast.Extent.Text
    ${Function:Get-HyperVLiveMigrationSettings}.Ast.Extent.Text
    ${Function:Get-HyperVMigrationSupport}.Ast.Extent.Text
    ${Function:Get-HyperVNumaSpanningSettings}.Ast.Extent.Text
    ${Function:Get-HyperVRoleInstalled}.Ast.Extent.Text
    ${Function:Get-HyperVStorageMigrationSettings}.Ast.Extent.Text
    ${Function:Get-ItemProperties}.Ast.Extent.Text
    ${Function:Get-ItemType}.Ast.Extent.Text
    ${Function:Get-LocalGroups}.Ast.Extent.Text
    ${Function:Get-LocalGroupUsers}.Ast.Extent.Text
    ${Function:Get-LocalUserBelongGroups}.Ast.Extent.Text
    ${Function:Get-LocalUsers}.Ast.Extent.Text
    ${Function:Get-MemorySummaryDownLevel}.Ast.Extent.Text
    ${Function:Get-Networks}.Ast.Extent.Text
    ${Function:Get-NetworkSummaryDownlevel}.Ast.Extent.Text
    ${Function:Get-NumberOfLoggedOnUsers}.Ast.Extent.Text
    ${Function:Get-ProcessDownlevel}.Ast.Extent.Text
    ${Function:Get-Processes}.Ast.Extent.Text
    ${Function:Get-ProcessHandle}.Ast.Extent.Text
    ${Function:Get-ProcessModule}.Ast.Extent.Text
    ${Function:Get-ProcessorSummaryDownlevel}.Ast.Extent.Text
    ${Function:Get-ProcessService}.Ast.Extent.Text
    ${Function:Get-RbacSessionConfiguration}.Ast.Extent.Text
    ${Function:Get-RegistrySubKeys}.Ast.Extent.Text
    ${Function:Get-RegistryValues}.Ast.Extent.Text
    ${Function:Get-RemoteDesktop}.Ast.Extent.Text
    ${Function:Get-RolesAndFeatures}.Ast.Extent.Text
    ${Function:Get-ScheduledTasks}.Ast.Extent.Text
    ${Function:Get-ServerConnectionStatus}.Ast.Extent.Text
    ${Function:Get-ServerInventory}.Ast.Extent.Text
    ${Function:Get-ServiceImagePath}.Ast.Extent.Text
    ${Function:Get-ServiceList}.Ast.Extent.Text
    ${Function:Get-ServiceLogOnUser}.Ast.Extent.Text
    ${Function:Get-ServiceRecoveryOptions}.Ast.Extent.Text
    ${Function:Get-StorageDisk}.Ast.Extent.Text
    ${Function:Get-StorageFileShare}.Ast.Extent.Text
    ${Function:Get-StorageQuota}.Ast.Extent.Text
    ${Function:Get-StorageResizeDetails}.Ast.Extent.Text
    ${Function:Get-StorageVolume}.Ast.Extent.Text
    ${Function:Get-TempFolder}.Ast.Extent.Text
    ${Function:Get-TempFolderPath}.Ast.Extent.Text
    ${Function:Get-TemporaryFolder}.Ast.Extent.Text
    ${Function:Get-WindowsUpdateInstallerStatus}.Ast.Extent.Text
    ${Function:Import-Certificate}.Ast.Extent.Text
    ${Function:Import-RegistryContent}.Ast.Extent.Text
    ${Function:Initialize-StorageDisk}.Ast.Extent.Text
    ${Function:Install-DeviceDriver}.Ast.Extent.Text
    ${Function:Install-RolesAndFeatures}.Ast.Extent.Text
    ${Function:Install-StorageFSRM}.Ast.Extent.Text
    ${Function:Install-WindowsUpdates}.Ast.Extent.Text
    ${Function:Mount-StorageVHD}.Ast.Extent.Text
    ${Function:New-BasicTask}.Ast.Extent.Text
    ${Function:New-CimProcessDump}.Ast.Extent.Text
    ${Function:New-EnvironmentVariable}.Ast.Extent.Text
    ${Function:New-FirewallRule}.Ast.Extent.Text
    ${Function:New-Folder}.Ast.Extent.Text
    ${Function:New-LocalGroup}.Ast.Extent.Text
    ${Function:New-LocalUser}.Ast.Extent.Text
    ${Function:New-ProcessDumpDownlevel}.Ast.Extent.Text
    ${Function:New-RegistryKey}.Ast.Extent.Text
    ${Function:New-RegistryValue}.Ast.Extent.Text
    ${Function:New-StorageQuota}.Ast.Extent.Text
    ${Function:New-StorageVHD}.Ast.Extent.Text
    ${Function:New-StorageVolume}.Ast.Extent.Text
    ${Function:Remove-AllShareNames}.Ast.Extent.Text
    ${Function:Remove-Certificate}.Ast.Extent.Text
    ${Function:Remove-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Remove-FilePath}.Ast.Extent.Text
    ${Function:Remove-FileSystemEntity}.Ast.Extent.Text
    ${Function:Remove-FirewallRule}.Ast.Extent.Text
    ${Function:Remove-FolderShareUser}.Ast.Extent.Text
    ${Function:Remove-ItemByPath}.Ast.Extent.Text
    ${Function:Remove-LocalGroup}.Ast.Extent.Text
    ${Function:Remove-LocalUser}.Ast.Extent.Text
    ${Function:Remove-LocalUserFromLocalGroups}.Ast.Extent.Text
    ${Function:Remove-RegistryKey}.Ast.Extent.Text
    ${Function:Remove-RegistryValue}.Ast.Extent.Text
    ${Function:Remove-ScheduledTask}.Ast.Extent.Text
    ${Function:Remove-ScheduledTaskAction}.Ast.Extent.Text
    ${Function:Remove-StorageQuota}.Ast.Extent.Text
    ${Function:Remove-StorageVolume}.Ast.Extent.Text
    ${Function:Remove-UsersFromLocalGroup}.Ast.Extent.Text
    ${Function:Rename-FileSystemEntity}.Ast.Extent.Text
    ${Function:Rename-LocalGroup}.Ast.Extent.Text
    ${Function:Rename-RegistryKey}.Ast.Extent.Text
    ${Function:Rename-RegistryValue}.Ast.Extent.Text
    ${Function:Resize-StorageVolume}.Ast.Extent.Text
    ${Function:Restart-CimOperatingSystem}.Ast.Extent.Text
    ${Function:Resume-CimService}.Ast.Extent.Text
    ${Function:Search-RegistryKeyAndValue}.Ast.Extent.Text
    ${Function:Set-AutomaticUpdatesOptions}.Ast.Extent.Text
    ${Function:Set-ComputerIdentification}.Ast.Extent.Text
    ${Function:Set-DeviceState}.Ast.Extent.Text
    ${Function:Set-DHCPIP}.Ast.Extent.Text
    ${Function:Set-EnvironmentVariable}.Ast.Extent.Text
    ${Function:Set-HyperVEnhancedSessionModeSettings}.Ast.Extent.Text
    ${Function:Set-HyperVHostGeneralSettings}.Ast.Extent.Text
    ${Function:Set-HyperVHostLiveMigrationSettings}.Ast.Extent.Text
    ${Function:Set-HyperVHostNumaSpanningSettings}.Ast.Extent.Text
    ${Function:Set-HyperVHostStorageMigrationSettings}.Ast.Extent.Text
    ${Function:Set-LocalGroupProperties}.Ast.Extent.Text
    ${Function:Set-LocalUserPassword}.Ast.Extent.Text
    ${Function:Set-LocalUserProperties}.Ast.Extent.Text
    ${Function:Set-RegistryValue}.Ast.Extent.Text
    ${Function:Set-RemoteDesktop}.Ast.Extent.Text
    ${Function:Set-ScheduledTaskConditions}.Ast.Extent.Text
    ${Function:Set-ScheduledTaskGeneralSettings}.Ast.Extent.Text
    ${Function:Set-ScheduledTaskSettingsSet}.Ast.Extent.Text
    ${Function:Set-ServiceLogOnUser}.Ast.Extent.Text
    ${Function:Set-ServiceRecoveryOptions}.Ast.Extent.Text
    ${Function:Set-ServiceStartOptions}.Ast.Extent.Text
    ${Function:Set-StaticIP}.Ast.Extent.Text
    ${Function:Set-StorageDiskOffline}.Ast.Extent.Text
    ${Function:Start-CimProcess}.Ast.Extent.Text
    ${Function:Start-CimService}.Ast.Extent.Text
    ${Function:Start-DiskPerf}.Ast.Extent.Text
    ${Function:Start-ProcessDownlevel}.Ast.Extent.Text
    ${Function:Start-ScheduledTask}.Ast.Extent.Text
    ${Function:Stop-CimOperatingSystem}.Ast.Extent.Text
    ${Function:Stop-CimProcess}.Ast.Extent.Text
    ${Function:Stop-DiskPerf}.Ast.Extent.Text
    ${Function:Stop-Processes}.Ast.Extent.Text
    ${Function:Stop-ScheduledTask}.Ast.Extent.Text
    ${Function:Stop-ServiceByName}.Ast.Extent.Text
    ${Function:Suspend-CimService}.Ast.Extent.Text
    ${Function:Test-FileSystemEntity}.Ast.Extent.Text
    ${Function:Test-RegistryValueExists}.Ast.Extent.Text
    ${Function:Uninstall-RolesAndFeatures}.Ast.Extent.Text
    ${Function:Update-Certificate}.Ast.Extent.Text
    ${Function:Update-DeviceDriver}.Ast.Extent.Text
    ${Function:Update-ScheduledTaskAction}.Ast.Extent.Text
    ${Function:Update-ScheduledTaskTrigger}.Ast.Extent.Text
    ${Function:Update-StorageQuota}.Ast.Extent.Text
)

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUGhobR81ke7irEbKkz6cYsnQn
# 1pagggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBxv5tskWnsV6HkA
# EhJ5CBHcpBM+MA0GCSqGSIb3DQEBAQUABIIBAEnfb2v0J6FLHQqLNmECNG0wKtwL
# 6QL17qxBnm/Jx3m3uE/enFFNUmYpErbZyle4zQfFVa6k44MBE205twbuXe56j5Yt
# im4UBO3iOgsp9RfGEriMwEtn2DzfwcG4cI6f2GSakDeiT5aRlTIp437vJh/I+Dm1
# /XrXQvlXMFiQuxEUmgPmVMLN2NYTg6mMCV8303P+tjhFXQzzVpmN8On/JX1aARw4
# T64NKOHvhmDF2IvCy4BZM4+VvoewEvtfa7rF2InPLBukG5Uq6vl02bUog0OmxQin
# TzQW2Zv8JAp4SLn17HfOj2ixgfBEGo5BxdyQY8C4fBVqxgtM6IldXe0f03o=
# SIG # End signature block
