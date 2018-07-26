
<#
    
    .SYNOPSIS
        Imports registry from an external file.
    
    .DESCRIPTION
        Imports registry from an exteranl file. The supported Operating Systems are
        Window Server 2012 and Windows Server 2012R2 and Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Import-RegistryContent {
    Param(
        [Parameter(Mandatory = $true)]
        [String]$file
        )
    
    $ErrorActionPreference = "Continue"
    $Error.Clear() 
    
    $LASTEXITCODE = 0      
    $tempFile = $env:TEMP + "\MsftSmeRegEditorImport.txt"
    
    Reg Import $file 2>$tempFile
    if ($LASTEXITCODE -ne 0) {
       throw  $Error[0].ToString()
    }
    
    Remove-Item $tempFile     
}