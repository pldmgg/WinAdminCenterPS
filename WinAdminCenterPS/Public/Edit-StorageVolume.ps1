<#
   
    .SYNOPSIS
        Update volume properties.
   
    .DESCRIPTION
        Update volume properties.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
   
    .ROLE
        Administrators
   
    .PARAMETER diskNumber
        The disk number.
   
    .PARAMETER partitionNumber
        The partition number.
   
    .PARAMETER oldDriveLetter
        Volume old dirve letter.
   
    .PARAMETER newVolumeName
        Volume new name.    
   
    .PARAMETER newDriveLetter
        Volume new dirve letter.
   
    .PARAMETER driveType
        Volume drive type.
   
#>
function Edit-StorageVolume {
    param (
       [String]
       $diskNumber,
       [uint32]
       $partitionNumber,
       [char]
       $newDriveLetter,
       [int]
       $driveType,
       [char]
       $oldDriveLetter,
       [String]
       $newVolumeName
   )
   
   Import-Module Microsoft.PowerShell.Management
   Import-Module Storage
   
   if($oldDriveLetter -ne $newDriveLetter) {
       if($driveType -eq 5 -or $driveType -eq 2)
       {
           $drv = Get-WmiObject win32_volume -filter "DriveLetter = '$($oldDriveLetter):'"
           $drv.DriveLetter = "$($newDriveLetter):"
           $drv.Put() | out-null
       } 
       else
       {
           Set-Partition -DiskNumber $diskNumber -PartitionNumber $partitionNumber -NewDriveLetter $newDriveLetter
       }
   }
   
   Set-Volume -DriveLetter $newDriveLetter -NewFileSystemLabel $newVolumeName
}
