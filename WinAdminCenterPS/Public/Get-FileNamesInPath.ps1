<#
    
    .SYNOPSIS
        Enumerates all of the file system entities (files, folders, volumes) of the system.
    
    .DESCRIPTION
        Enumerates all of the file system entities (files, folders, volumes) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
    
    .ROLE
        Readers

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .PARAMETER Path
        String -- The path to enumerate.
    
    .PARAMETER OnlyFolders
        switch -- 
    
#>
function Get-FileNamesInPath {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $false)]
        [switch]
        $OnlyFolders
    )
    
    Set-StrictMode -Version 5.0
    
    function isFolder($item) {
        return $item.Attributes -match "Directory" -or $item.Attributes -match "ReparsePoint"
    }
    
    function getName($item) {
        $slash = '';
    
        if (isFolder $item) {
            $slash = '\';
        }
    
        return "$($_.Name)$slash"
    }
    
    if ($onlyFolders) {
        return (Get-ChildItem -Path $Path | Where-Object {isFolder $_}) | ForEach-Object { return "$($_.Name)\"} | Sort-Object
    }
    
    return (Get-ChildItem -Path $Path) | ForEach-Object { return getName($_)} | Sort-Object
    
}