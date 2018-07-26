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