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
