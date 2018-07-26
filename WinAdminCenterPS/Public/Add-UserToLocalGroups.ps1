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