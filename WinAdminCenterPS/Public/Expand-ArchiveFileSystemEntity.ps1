<#
    
    .SYNOPSIS
        Expands the specified file system entity (files, folders) of the system.
    
    .DESCRIPTION
        Expands the specified file system entity (files, folders) of the system on this server.
        The supported Operating Systems are Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
    .PARAMETER PathSource
        String -- The path to expand.
    
    .PARAMETER PathDestination
        String -- The destination path to expand into.
    
    .PARAMETER Force
        boolean -- override any confirmations
    
#>
function Expand-ArchiveFileSystemEntity {
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $PathSource,    
    
        [Parameter(Mandatory = $true)]
        [String]
        $PathDestination,
    
        [Parameter(Mandatory = $false)]
        [boolean]
        $Force
    )
    
    Set-StrictMode -Version 5.0
    
    if ($Force) {
        Expand-Archive -Path $PathSource -Force -DestinationPath $PathDestination
    } else {
        Expand-Archive -Path $PathSource -DestinationPath $PathDestination
    }
    
    if ($error) {
        $code = $error[0].Exception.HResult
        @{ status = "error"; code = $code; message = $error }
    } else {
        @{ status = "ok"; }
    }    
}