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
