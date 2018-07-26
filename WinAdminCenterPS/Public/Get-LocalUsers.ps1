<#
    
    .SYNOPSIS
        Gets the local users.
    
    .DESCRIPTION
        Gets the local users. The supported Operating Systems are
        Window Server 2012, Windows Server 2012R2, Windows Server 2016.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-LocalUsers {
    param (
        [Parameter(Mandatory = $false)]
        [String]
        $SID
    )
    
    $isWinServer2016OrNewer = [Environment]::OSVersion.Version.Major -ge 10;
    # ADSI does NOT support 2016 Nano, meanwhile New-LocalUser, Get-LocalUser, Set-LocalUser do NOT support downlevel
    if ($SID)
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser -SID $SID | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                                Description,
                                                Enabled,
                                                FullName,
                                                LastLogon,
                                                Name,
                                                ObjectClass,
                                                PasswordChangeableDate,
                                                PasswordExpires,
                                                PasswordLastSet,
                                                PasswordRequired,
                                                @{Name="SID"; Expression={$_.SID.Value}},
                                                UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' AND SID='$SID'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }
    else
    {
        if ($isWinServer2016OrNewer)
        {
            Get-LocalUser | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpires,
                                    Description,
                                    Enabled,
                                    FullName,
                                    LastLogon,
                                    Name,
                                    ObjectClass,
                                    PasswordChangeableDate,
                                    PasswordExpires,
                                    PasswordLastSet,
                                    PasswordRequired,
                                    @{Name="SID"; Expression={$_.SID.Value}},
                                    UserMayChangePassword;
        }
        else
        {
            Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Sort-Object -Property Name | Microsoft.PowerShell.Utility\Select-Object AccountExpirationDate,
                                                                                            Description,
                                                                                            @{Name="Enabled"; Expression={-not $_.Disabled}},
                                                                                            FullName,
                                                                                            LastLogon,
                                                                                            Name,
                                                                                            ObjectClass,
                                                                                            PasswordChangeableDate,
                                                                                            PasswordExpires,
                                                                                            PasswordLastSet,
                                                                                            PasswordRequired,
                                                                                            SID,
                                                                                            @{Name="UserMayChangePassword"; Expression={$_.PasswordChangeable}}
        }
    }    
}