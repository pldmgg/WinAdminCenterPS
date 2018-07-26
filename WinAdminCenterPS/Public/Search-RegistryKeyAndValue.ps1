<#
    
    .SYNOPSIS
        Search Registry key, value name, value data under the selected key.
    
    .DESCRIPTION
        Search Registry key, value name, value data under the selected key. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.
    
    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.

    .ROLE
        Readers
    
#>
function Search-RegistryKeyAndValue {
    Param(
        [Parameter(Mandatory = $true)]
        [string]$path,
        [Parameter(Mandatory = $true)]
        [String]$SearchTerm
        )
    
    $ErrorActionPreference = "Stop"    
                    
    $global:results = @()
    $Error.Clear()                   
    function CreateEntry([string] $entryName, [string] $entryType ='', [string] $entryData=''){
        $valueEntry = New-Object System.Object
        $valueEntry | Add-Member -type NoteProperty -name Name -value $entryName  
    
        $valueEntry | Add-Member -type NoteProperty -name type -value $entryType
        $valueEntry | Add-Member -type NoteProperty -name data -value  $entryData
        return $valueEntry
    }
    
    function SearchRegKeyValue([object] $Keys){
        foreach ($Key in $Keys){
            if ($Key.PSChildName -match $SearchTerm) {  
                $global:results += CreateEntry $key.PSPath 
            }  
    
            $valueNames = $Key.GetValueNames()
            foreach($valName in $valueNames){
                if ($valName -match $SearchTerm) {  
                    $valPath = $key.PSPath + '\\'+ $valName
                    $global:results += CreateEntry $valPath $key.GetValueKind($valName) $key.GetValue($valName)
                }  
    
                if (($valName | % { $Key.GetValue($_) }) -match $SearchTerm) {  
                    $valPath = $key.PSPath + '\\'+ $valName
                    $global:results += CreateEntry $valPath $key.GetValueKind($valName) $key.GetValue($valName)
                } 
            } 
        }
    }
    
    $curItem = Get-Item $path
    SearchRegKeyValue $curItem 
    
    $childItems = Get-ChildItem $path -ErrorAction SilentlyContinue -Recurse
    SearchRegKeyValue $childItems 
    
    $global:results    
}