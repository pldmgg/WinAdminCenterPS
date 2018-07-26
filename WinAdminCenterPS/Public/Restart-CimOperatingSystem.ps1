<#
    
    .SYNOPSIS
        Reboot Windows Operating System by using Win32_OperatingSystem provider.
    
    .DESCRIPTION
        Reboot Windows Operating System by using Win32_OperatingSystem provider.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Administrators
    
#>
function Restart-CimOperatingSystem {
    Param(
    )
    
    import-module CimCmdlets
    
    Invoke-CimMethod -Namespace root/cimv2 -ClassName Win32_OperatingSystem -MethodName Reboot
    
}