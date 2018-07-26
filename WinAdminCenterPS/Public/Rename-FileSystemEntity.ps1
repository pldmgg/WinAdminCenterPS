<#
    
    .SYNOPSIS
        Rename a folder.
    
    .DESCRIPTION
        Rename a folder on this server.
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
        String -- the path to the folder.
    
    .PARAMETER NewName
        String -- the new folder name.
    
#>
function Rename-FileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $NewName
    )
    
    Set-StrictMode -Version 5.0
    
    <#
    .Synopsis
        Name: Get-FileSystemEntityType
        Description: Gets the type of a local file system entity.
    
    .Parameters
        $Attributes: The System.IO.FileAttributes of the FileSystemEntity.
    
    .Returns
        The type of the local file system entity.
    #>
    function Get-FileSystemEntityType
    {
        param (
            [Parameter(Mandatory = $true)]
            [System.IO.FileAttributes]
            $Attributes
        )
    
        if ($Attributes -match "Directory" -or $Attributes -match "ReparsePoint")
        {
            return "Folder";
        }
        else
        {
            return "File";
        }
    }
    
    Rename-Item -Path $Path -NewName $NewName -PassThru |
        Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                    @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                    Extension,
                    @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                    Name,
                    @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                    @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                    @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};
    
}