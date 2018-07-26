<#
    
    .SYNOPSIS
        Gets the number of logged on users.
    
    .DESCRIPTION
        Gets the number of logged on users including active and disconnected users.
        Returns a count of users.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
    
#>
function Get-NumberOfLoggedOnUsers {
    $count = 0
    $error.Clear();
    
    # query user may return an uncatchable error. We need to redirect it.
    # Sends errors (2) and success output (1) to the success output stream.
    $result = query user 2>&1
    
    if ($error.Count -EQ 0)
    {
        # query user does not return a valid ps object and includes the header.
        # subtract 1 to get actual count.
        $count = $result.count -1
    }
    
    @{Count = $count}
}