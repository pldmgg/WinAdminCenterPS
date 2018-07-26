<#
    
    .SYNOPSIS
        Enumerates the root of the file system (volumes and related entities) of the system.
    
    .DESCRIPTION
        Enumerates the root of the file system (volumes and related entities) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-FileSystemRoot {
    Set-StrictMode -Version 5.0
    import-module CimCmdlets
    
    <#
    .Synopsis
        Name: Get-FileSystemRoot
        Description: Gets the local file system root entities of the machine.
    
    .Returns
        The local file system root entities.
    #>
    function Get-FileSystemRoot
    {
        $volumes = Enumerate-Volumes;
    
        return $volumes |
            Microsoft.PowerShell.Utility\Select-Object @{Name="Caption"; Expression={$_.DriveLetter +":\"}},
                            @{Name="CreationDate"; Expression={$null}},
                            @{Name="Extension"; Expression={$null}},
                            @{Name="IsHidden"; Expression={$false}},
                            @{Name="Name"; Expression={if ($_.FileSystemLabel) { $_.FileSystemLabel + " (" + $_.DriveLetter + ":)"} else { "(" + $_.DriveLetter + ":)" }}},
                            @{Name="Type"; Expression={"Volume"}},
                            @{Name="LastModifiedDate"; Expression={$null}},
                            @{Name="Size"; Expression={$_.Size}},
                            @{Name="SizeRemaining"; Expression={$_.SizeRemaining}}
    }
    
    <#
    .Synopsis
        Name: Get-Volumes
        Description: Gets the local volumes of the machine.
    
    .Returns
        The local volumes.
    #>
    function Enumerate-Volumes
    {
        Remove-Module Storage -ErrorAction Ignore; # Remove the Storage module to prevent it from automatically localizing
    
        $isDownlevel = [Environment]::OSVersion.Version.Major -lt 10;
        if ($isDownlevel)
        {
            $disks = Get-CimInstance -ClassName MSFT_Disk -Namespace root/Microsoft/Windows/Storage | Where-Object { !$_.IsClustered };
            $partitions = $disks | Get-CimAssociatedInstance -ResultClassName MSFT_Partition;
            if (($partitions -eq $null) -or ($partitions.Length -eq 0)) {
                $volumes = Get-CimInstance -ClassName MSFT_Volume -Namespace root/Microsoft/Windows/Storage;
            } else {
                $volumes = $partitions | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
            }
        }
        else
        {
            $subsystem = Get-CimInstance -ClassName MSFT_StorageSubSystem -Namespace root/Microsoft/Windows/Storage| Where-Object { $_.FriendlyName -like "Win*" };
            $volumes = $subsystem | Get-CimAssociatedInstance -ResultClassName MSFT_Volume;
        }
    
        return $volumes | Where-Object { [byte]$_.DriveLetter -ne 0 -and $_.DriveLetter -ne $null -and $_.Size -gt 0 };
    }
    
    Get-FileSystemRoot;
    
}