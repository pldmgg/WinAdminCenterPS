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