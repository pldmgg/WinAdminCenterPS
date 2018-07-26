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
        String -- the path to the folder where enumeration should start.
    
#>
function Get-ItemType {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path
    )
    
    Set-StrictMode -Version 5.0
    
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
    
    if (Test-Path -LiteralPath $Path) {
        return Get-FileSystemEntityType -Attributes (Get-Item $Path).Attributes
    } else {
        return ''
    }
    
}