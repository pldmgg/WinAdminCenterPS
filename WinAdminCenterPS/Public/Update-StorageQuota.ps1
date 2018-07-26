<#
   
    .SYNOPSIS
        Update a new Quota for volume.
   
    .DESCRIPTION
        Update a new Quota for volume.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.
   
    .ROLE
        Administrators
   
    .PARAMETER disabledQuota
        Enable or disable quota.
   
    .PARAMETER path
        Path of the quota.
   
    .PARAMETER size
        The size of quota.
   
    .PARAMETER softLimit
        Deny if usage exceeding quota limit.
   
#>
function Update-StorageQuota {
   param
   (
       # Enable or disable quota.
       [Parameter(Mandatory = $true)]
       [Boolean]
       $disabledQuota,
   
       # Path of the quota.
       [Parameter(Mandatory = $true)]
       [String]
       $path,
   
       # The size of quota.
       [Parameter(Mandatory = $true)]
       [String]
       $size,
   
       # Deny if usage exceeding quota limit.
       [Parameter(Mandatory = $true)]
       [Boolean]
       $softLimit
   )
   Import-Module FileServerResourceManager
   
   $scriptArguments = @{
       Path = $path
       Disabled = $disabledQuota
       SoftLimit = $softLimit
   }
   
   if ($size) {
       $scriptArguments.Size = $size
   }
   
   Set-FsrmQuota @scriptArguments
   
}