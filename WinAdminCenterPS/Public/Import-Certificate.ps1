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