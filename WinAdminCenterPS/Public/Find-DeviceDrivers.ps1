<#
    
    .SYNOPSIS
        Search drivers online.
    
    .DESCRIPTION
        Search drivers online.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Find-DeviceDrivers {
    param(
        [String]$model
    )
    
     $Session = New-Object -ComObject Microsoft.Update.Session           
     
     $Searcher = $Session.CreateUpdateSearcher() 
     $Searcher.ServiceID = '7971f918-a847-4430-9279-4a52d1efe18d'
     $Searcher.SearchScope =  1 # MachineOnly
     $Searcher.ServerSelection = 3 # Third Party
     
     $Criteria = "IsInstalled=0 and Type='Driver'"
     $SearchResult = $Searcher.Search($Criteria) 
     
     $Updates = $SearchResult.Updates          
     
     if ($model) {
        $Updates = $Updates | Where-Object {$_.driverModel -eq $model} 
     }
     
     $Updates    
}