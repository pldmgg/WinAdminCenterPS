<#
    
    .SYNOPSIS
        Enumerates all of the file system entities (files, folders, volumes) of the system.
    
    .DESCRIPTION
        Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER Path
        String -- The path to enumerate.
    
    .PARAMETER OnlyFiles
        switch -- 
    
    .PARAMETER OnlyFolders
        switch -- 
    
#>
function Get-FileSystemEntities {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $false)]
        [Switch]
        $OnlyFiles,
    
        [Parameter(Mandatory = $false)]
        [Switch]
        $OnlyFolders
    )
    
    Set-StrictMode -Version 5.0
    
    <#
    .Synopsis
        Name: Get-FileSystemEntities
        Description: Gets all the local file system entities of the machine.
    
    .Parameter Path
        String -- The path to enumerate.
    
    .Returns
        The local file system entities.
    #>
    function Get-FileSystemEntities
    {
        param (
            [Parameter(Mandatory = $true)]
            [String]
            $Path
        )
    
        return Get-ChildItem -Path $Path -Force |
            Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                            @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                            Extension,
                            @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                            Name,
                            @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                            @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                            @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};
    }
    
    <#
    .Synopsis
        Name: Get-FileSystemEntityType
        Description: Gets the type of a local file system entity.
    
    .Parameter Attributes
        The System.IO.FileAttributes of the FileSystemEntity.
    
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
    
    $entities = Get-FileSystemEntities -Path $Path;
    if ($OnlyFiles -and $OnlyFolders)
    {
        return $entities;
    }
    
    if ($OnlyFiles)
    {
        return $entities | Where-Object { $_.Type -eq "File" };
    }
    
    if ($OnlyFolders)
    {
        return $entities | Where-Object { $_.Type -eq "Folder" };
    }
    
    return $entities;
    
}