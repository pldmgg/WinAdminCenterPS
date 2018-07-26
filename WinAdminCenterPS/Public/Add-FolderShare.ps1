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