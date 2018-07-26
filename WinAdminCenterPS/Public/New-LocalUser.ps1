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