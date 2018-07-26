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