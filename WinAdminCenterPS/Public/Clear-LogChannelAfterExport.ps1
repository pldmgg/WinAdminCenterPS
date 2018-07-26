<#
    
    .SYNOPSIS
        Clear the event log channel after export the event log channel file (.evtx).
    
    .DESCRIPTION
        Clear the event log channel after export the event log channel file (.evtx).
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Clear-EventLogChannelAfterExport {
    Param(
        [string]$channel
    )
    
    $segments = $channel.Split("-")
    $name = $segments[-1]
    
    $randomString = [GUID]::NewGuid().ToString()
    $ResultFile = $env:temp + "\" + $name + "_" + $randomString + ".evtx"
    $ResultFile = $ResultFile -replace "/", "-"
    
    wevtutil epl "$channel" "$ResultFile" /ow:true
    
    [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog("$channel") 
    
    return $ResultFile
    
}