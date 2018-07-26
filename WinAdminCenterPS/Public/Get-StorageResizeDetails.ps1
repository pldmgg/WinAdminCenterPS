<#
    
    .SYNOPSIS
        Get disk and volume space details required for resizing volume.
    
    .DESCRIPTION
        Get disk and volume space details required for resizing volume.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
    .PARAMETER driveLetter
        The drive letter
    
#> 
function Get-StorageResizeDetails {
     param (
            [Parameter(Mandatory = $true)]
            [String]
            $driveLetter
        )
    Import-Module Storage
    
    # Get volume details
    $volume = get-Volume -DriveLetter $driveLetter
    
    $volumeTotalSize = $volume.Size
    
    # Get partition details by drive letter
    $partition = get-Partition -DriveLetter $driveLetter
    
    $partitionNumber =$partition.PartitionNumber
    $diskNumber = $partition.DiskNumber
    
    $disk = Get-Disk -Number $diskNumber
    
    $totalSize = $disk.Size
    
    $allocatedSize = $disk.AllocatedSize
    
    # get unallocated space on the disk
    $unAllocatedSize = $totalSize - $allocatedSize
    
    $sizes = Get-PartitionSupportedSize -DiskNumber $diskNumber -PartitionNumber $partitionNumber
    
    $resizeDetails=@{
      "volumeTotalSize" = $volumeTotalSize;
      "unallocatedSpaceSize" = $unAllocatedSize;
      "minSize" = $sizes.sizeMin;
      "maxSize" = $sizes.sizeMax;
     }
    
     return $resizeDetails
}