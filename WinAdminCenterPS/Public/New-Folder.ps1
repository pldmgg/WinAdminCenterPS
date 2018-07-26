<#
    
    .SYNOPSIS
        Create a new folder.
    
    .DESCRIPTION
        Create a new folder on this server.
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
        String -- the path to the parent of the new folder.
    
    .PARAMETER NewName
        String -- the folder name.
    
#>
function New-Folder {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,
    
        [Parameter(Mandatory = $true)]
        [String]
        $NewName
    )
    
    Set-StrictMode -Version 5.0
    
    $pathSeparator = [System.IO.Path]::DirectorySeparatorChar;
    $newItem = New-Item -ItemType Directory -Path ($Path.TrimEnd($pathSeparator) + $pathSeparator + $NewName)
    
    return $newItem |
        Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.FullName}},
                        @{Name="CreationDate"; Expression={$_.CreationTimeUtc}},
                        Extension,
                        @{Name="IsHidden"; Expression={$_.Attributes -match "Hidden"}},
                        Name,
                        @{Name="Type"; Expression={Get-FileSystemEntityType -Attributes $_.Attributes}},
                        @{Name="LastModifiedDate"; Expression={$_.LastWriteTimeUtc}},
                        @{Name="Size"; Expression={if ($_.PSIsContainer) { $null } else { $_.Length }}};
    
}