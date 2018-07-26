<#
    
    .SYNOPSIS
        Get information about the driver inf file
    
    .DESCRIPTION
        Get information about the driver inf file

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Get-DeviceDriverInformation {
    param(
        [String]$path,
        [bool]$recursive,
        [String]$classguid
    )
    
    $driversCollection = (Get-ChildItem -Path "$path" -Filter "*.inf" -recurse:$recursive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Fullname)
    
    Foreach ($Driver in $driversCollection)
    {
        $GUID = ""
        $Version = ""
        $Provider = ""
    
        $content = Get-Content -Path "$Driver"
    
        $line = ($content  | Select-String "ClassGuid")
        if ($line -ne $null) {
            $GUID = $line.Line.Split('=')[-1].Split(' ').Split(';')
            $GUID = ([string]$GUID).trim()
        }
    
        $line = ($content  | Select-String "DriverVer")
        if ($line -ne $null) {
            $Version = $line.Line.Split('=')[-1].Split(' ').Split(';')
            $Version = ([string]$Version).trim()
        }
       
        $line = ($content  | Select-String "Provider")
        if ($line -ne $null) {
            $Provider = $line.Line.Split('=')[-1].Split(' ').Split(';')
            $Provider = ([string]$Provider).trim()
        }
    
        if ($classguid -eq $GUID){
            Write-Output "$Driver,$Provider,$Version,$GUID"
        }
    }    
}