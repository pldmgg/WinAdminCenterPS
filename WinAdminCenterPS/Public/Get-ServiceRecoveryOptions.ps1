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