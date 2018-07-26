<#
    .SYNOPSIS
        This function is meant to make it easy to configure both the SSH Client and SSHD Server for Public
        Certificate Authentication. It can (and should) be run on BOTH the SSH Client and the SSHD Server.

        This function does the following:
            - Uses the Vault Server's SSH Host Signing Certificate Authority (CA) to sign the local host's
            ssh host key (i.e. 'C:\ProgramData\ssh\ssh_host_rsa_key.pub', resulting in
            C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub)
            - Gets the Public Key of the CA used to sign User/Client SSH Keys from the Vault Server and adds it to:
                1) The file C:\ProgramData\ssh\authorized_keys as a string;
                2) The file C:\ProgramData\ssh\ssh_known_hosts as a string; and
                3) The dedicated file C:\ProgramData\ssh\ca_pub_key_of_client_signer.pub
            - Gets the Public Key of the CA used to sign Host/Machine SSH Keys from the Vault Server and adds it to:
                1) The file C:\ProgramData\ssh\authorized_keys as a string;
                2) The file C:\ProgramData\ssh\ssh_known_hosts as a string; and
                3) The dedicated file C:\ProgramData\ssh\ca_pub_key_of_host_signer.pub
            - Adds references to user accounts that you would like to grant ssh access to the local machine
            to C:\ProgramData\ssh\authorized_principals (includes both Local and Domain users)
            - Ensures NTFS filesystem permissions are set appropriately for the aforementioned files
            - Adds references to 'TrustedUserCAKeys' and 'AuthorizedPrincipalsFile' to
            C:\ProgramData\ssh\sshd_config

        IMPORTANT NOTE: Just in case any breaking/undesireable changes are made to the host's ssh configuration,
        all files that could potentially be changed are backed up to C:\ProgramData\ssh\Archive before any
        changes are actually made.

    .DESCRIPTION
        See .SYNOPSIS

    .NOTES

    .PARAMETER PublicKeyOfCAUsedToSignUserKeysFilePath
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignUserKeysFilePath,
        -PublicKeyOfCAUsedToSignUserKeysAsString, or -PublicKeyOfCAUsedToSignUserKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents a path to a file that is the Public Key of the CA
        used to sign SSH User/Client Keys.

    .PARAMETER PublicKeyOfCAUsedToSignUserKeysAsString
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignUserKeysFilePath,
        -PublicKeyOfCAUsedToSignUserKeysAsString, or -PublicKeyOfCAUsedToSignUserKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the Public Key of the CA used to sign SSH User/Client
        Keys. The string must start with "ssh-rsa".

    .PARAMETER PublicKeyOfCAUsedToSignUserKeysVaultUrl
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignUserKeysFilePath,
        -PublicKeyOfCAUsedToSignUserKeysAsString, or -PublicKeyOfCAUsedToSignUserKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the URL of the Vault Server Rest API Endpoint that
        advertises the Public Key of the CA used to sign SSH User/Client Keys. The URL should be something like:
            https://<FQDNOfVaultServer>:8200/v1/ssh-client-signer/public_key

    .PARAMETER PublicKeyOfCAUsedToSignHostKeysFilePath
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignHostKeysFilePath,
        -PublicKeyOfCAUsedToSignhostKeysAsString, or -PublicKeyOfCAUsedToSignHostKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents a path to a file that is the Public Key of the CA
        used to sign SSH Host/Machine Keys.

    .PARAMETER PublicKeyOfCAUsedToSignHostKeysAsString
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignHostKeysFilePath,
        -PublicKeyOfCAUsedToSignhostKeysAsString, or -PublicKeyOfCAUsedToSignHostKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the Public Key of the CA used to sign SSH Host/Machine
        Keys. The string must start with "ssh-rsa".

    .PARAMETER PublicKeyOfCAUsedToSignHostKeysVaultUrl
        This parameter is OPTIONAL, however, either -PublicKeyOfCAUsedToSignHostKeysFilePath,
        -PublicKeyOfCAUsedToSignhostKeysAsString, or -PublicKeyOfCAUsedToSignHostKeysVaultUrl is REQUIRED.

        This parameter takes a string that represents the URL of the Vault Server REST API Endpoint that
        advertises the Public Key of the CA used to sign SSH User/Client Keys. The URL should be something like:
            https://<FQDNOfVaultServer>:8200/v1/ssh-host-signer/public_key

    .PARAMETER AuthorizedUserPrincipals
        This parameter is OPTIONAL, but highly recommended.

        This parameter takes an array of strings, each of which represents either a Local User Account
        or a Domain User Account. Local User Accounts MUST be in the format <UserName>@<LocalHostComputerName> and
        Domain User Accounts MUST be in the format <UserName>@<DomainPrefix>. (To clarify DomainPrefix: if your
        domain is, for example, 'zero.lab', your DomainPrefix would be 'zero').

        These strings will be added to the file C:\ProgramData\ssh\authorized_principals, and these User Accounts
        will be permitted to SSH into the machine that this function is run on.

        You CAN use this parameter in conjunction with the -AuthorizedPrincipalsUserGroup parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .PARAMETER AuthorizedPrincipalsUserGroup
        This parameter is OPTIONAL.

        This parameter takes an array of strings that can be any combination of the following values:
            - AllUsers
            - LocalAdmins
            - LocalUsers
            - DomainAdmins
            - DomainUsers
        
        The value 'AllUsers' is the equivalent of specifying 'LocalAdmins','LocalUsers','DomainAdmins', and
        'DomainUsers'.

        Each User Account that is a member of the specified groups will be added to the file
        C:\ProgramData\ssh\authorized_principals, and these User Accounts will be permitted to SSH into the machine
        that this function is run on.

        You CAN use this parameter in conjunction with the -AuthorizedUserPrincipals parameter, and this function
        DOES check for repeats, so don't worry about overlap.

    .PARAMETER VaultSSHHostSigningUrl
        This parameter is OPTIONAL, but highly recommended.

        This parameter takes a string that represents the URL of the Vault Server REST API endpoint that is
        responsible for signing the Local Host's Host/Machine SSH Key. The URL should be something like:
            http://<FQDNOfVaultServer>:8200/v1/ssh-host-signer/sign/hostrole

        Using this parameter outputs the signed SSH Host/Machine Key file C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub

    .PARAMETER VaultAuthToken
        This parameter is OPTIONAL, but becomes MANDATORY if you use the -VaultSSHHostSigningUrl parameter.
        It should only be used if you use the -VaultSSHHostSigningUrl parameter.

        This parameter takes a string that represents a Vault Authentiction token with permission to
        request that the Vault Server sign the Local Host's SSH Host/Machine Key.

    .EXAMPLE
        # Open an elevated PowerShell Session, import the module, and -
        
        PS C:\Users\zeroadmin> $AddCAPubKeyToSSHAndSSHDConfigSplatParams = @{
            PublicKeyOfCAUsedToSignUserKeysVaultUrl     = "$VaultServerBaseUri/ssh-client-signer/public_key"
            PublicKeyOfCAUsedToSignHostKeysVaultUrl     = "$VaultServerBaseUri/ssh-host-signer/public_key"
            AuthorizedPrincipalsUserGroup               = @("LocalAdmins","DomainAdmins")
            VaultSSHHostSigningUrl                      = "$VaultServerBaseUri/ssh-host-signer/sign/hostrole"
            VaultAuthToken                              = $ZeroAdminToken
        }
        PS C:\Users\zeroadmin> $AddCAPubKeysResult = Add-CAPubKeyToSSHAndSSHDConfig @AddCAPubKeyToSSHAndSSHDConfigSplatParams
#>
function Add-CAPubKeyToSSHAndSSHDConfig {
    [CmdletBinding(DefaultParameterSetName='VaultUrl')]
    Param(
        # NOTE: When reading 'PathToPublicKeyOfCAUsedToSign', please note that it is actually the CA's
        # **private key** that is used to do the signing. We just require the CA's public key to verify
        # that presented user keys signed by the CA's private key were, in fact, signed by the CA's private key
        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysFilePath,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysAsString,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignUserKeysVaultUrl, # Should be something like: http://192.168.2.12:8200/v1/ssh-client-signer/public_key

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysFilePath,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysAsString,

        [Parameter(Mandatory=$False)]
        [string]$PublicKeyOfCAUsedToSignHostKeysVaultUrl, # Should be something like: http://192.168.2.12:8200/v1/ssh-host-signer/public_key

        [Parameter(Mandatory=$False)]
        [ValidatePattern("[\w]+@[\w]+")]
        [string[]]$AuthorizedUserPrincipals,

        [Parameter(Mandatory=$False)]
        [ValidateSet("AllUsers","LocalAdmins","LocalUsers","DomainAdmins","DomainUsers")]
        [string[]]$AuthorizedPrincipalsUserGroup,

        # Use the below $VaultSSHHostSigningUrl and $VaultAuthToken parameters if you want
        # C:\ProgramData\ssh\ssh_host_rsa_key.pub signed by the Vault Host Signing CA. This is highly recommended.
        [Parameter(Mandatory=$False)]
        [string]$VaultSSHHostSigningUrl, # Should be something like http://192.168.2.12:8200/v1/ssh-host-signer/sign/hostrole"

        [Parameter(Mandatory=$False)]
        [string]$VaultAuthToken
    )

    if ($($PSBoundParameters.Keys -match "UserKeys").Count -gt 1) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) only takes one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignUserKeysFilePath, -PublicKeyOfCAUsedToSignUserKeysAsString, -PublicKeyOfCAUsedToSignUserKeysVaultUrl"
        Write-Error $ErrMsg
    }
    if ($($PSBoundParameters.Keys -match "UserKeys").Count -eq 0) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) MUST use one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignUserKeysFilePath, -PublicKeyOfCAUsedToSignUserKeysAsString, -PublicKeyOfCAUsedToSignUserKeysVaultUrl"
        Write-Error $ErrMsg
    }

    if ($($PSBoundParameters.Keys -match "HostKeys").Count -gt 1) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) only takes one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignHostKeysFilePath, -PublicKeyOfCAUsedToSignHostKeysAsString, -PublicKeyOfCAUsedToSignHostKeysVaultUrl"
        Write-Error $ErrMsg
    }
    if ($($PSBoundParameters.Keys -match "HostKeys").Count -eq 0) {
        $ErrMsg = "The $($MyInvocation.MyCommand.Name) MUST use one of the following parameters: " +
        "-PublicKeyOfCAUsedToSignHostKeysFilePath, -PublicKeyOfCAUsedToSignHostKeysAsString, -PublicKeyOfCAUsedToSignHostKeysVaultUrl"
        Write-Error $ErrMsg
    }

    if (!$AuthorizedUserPrincipals -and !$AuthorizedPrincipalsUserGroup) {
        $AuthPrincErrMsg = "The $($MyInvocation.MyCommand.Name) function requires one of the following parameters: " +
        "-AuthorizedUserPrincipals, -AuthorizedPrincipalsUserGroup"
        Write-Error $AuthPrincErrMsg
        $global:FunctionResult = "1"
        return
    }

    if ($($VaultSSHHostSigningUrl -and !$VaultAuthToken) -or $(!$VaultSSHHostSigningUrl -and $VaultAuthToken)) {
        $ErrMsg = "If you would like this function to facilitate signing $env:ComputerName's ssh_host_rsa_key.pub, " +
        "both -VaultSSHHostSigningUrl and -VaultAuthToken parameters are required! Halting!"
        Write-Error $ErrMsg
        $global:FunctionResult = "1"
        return
    }

    # Setup our $Output Hashtable which we will add to as necessary as we go
    [System.Collections.ArrayList]$FilesUpdated = @()
    $Output = @{
        FilesUpdated = $FilesUpdated
    }


    # Make sure sshd service is installed and running. If it is, we shouldn't need to use
    # the New-SSHD server function
    if (![bool]$(Get-Service sshd -ErrorAction SilentlyContinue)) {
        if (![bool]$(Get-Service ssh-agent -ErrorAction SilentlyContinue)) {
            $InstallWinSSHSplatParams = @{
                GiveWinSSHBinariesPathPriority  = $True
                ConfigureSSHDOnLocalHost        = $True
                DefaultShell                    = "powershell"
                GitHubInstall                   = $True
                ErrorAction                     = "SilentlyContinue"
                ErrorVariable                   = "IWSErr"
            }

            try {
                $InstallWinSSHResults = Install-WinSSH @InstallWinSSHSplatParams -ErrorAction Stop
                if (!$InstallWinSSHResults) {throw "There was a problem with the Install-WinSSH function! Halting!"}

                $Output.Add("InstallWinSSHResults",$InstallWinSSHResults)
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the Install-WinSSH function are as follows:"
                Write-Error $($IWSErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
        else {
            $NewSSHDServerSplatParams = @{
                ErrorAction         = "SilentlyContinue"
                ErrorVariable       = "SSHDErr"
                DefaultShell        = "powershell"
            }
            
            try {
                $NewSSHDServerResult = New-SSHDServer @NewSSHDServerSplatParams
                if (!$NewSSHDServerResult) {throw "There was a problem with the New-SSHDServer function! Halting!"}
            }
            catch {
                Write-Error $_
                Write-Host "Errors for the New-SSHDServer function are as follows:"
                Write-Error $($SSHDErr | Out-String)
                $global:FunctionResult = "1"
                return
            }
        }
    }

    if (Test-Path "$env:ProgramData\ssh\sshd_config") {
        $sshdir = "$env:ProgramData\ssh"
        $sshdConfigPath = "$sshdir\sshd_config"
    }
    elseif (Test-Path "$env:ProgramFiles\OpenSSH-Win64\sshd_config") {
        $sshdir = "$env:ProgramFiles\OpenSSH-Win64"
        $sshdConfigPath = "$env:ProgramFiles\OpenSSH-Win64\sshd_config"
    }
    if (!$sshdConfigPath) {
        Write-Error "Unable to find file 'sshd_config'! Halting!"
        $global:FunctionResult = "1"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        return
    }

    if ($VaultSSHHostSigningUrl) {
        # Make sure $VaultSSHHostSigningUrl is a valid Url
        try {
            $UriObject = [uri]$VaultSSHHostSigningUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignUserKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        # Try to sign this machine's host key (i.e. C:\ProgramData\ssh\ssh_host_rsa_key.pub)
        try {
            # The below 'Sign-SSHHostPublicKey' function outputs a PSCustomObject detailing what was done
            # to the sshd config (if anything). It also writes out C:\ProgramData\ssh\ssh_host_rsa_key-cert.pub
            $SignSSHHostKeySplatParams = @{
                VaultSSHHostSigningUrl      = $VaultSSHHostSigningUrl
                VaultAuthToken              = $VaultAuthToken
                ErrorAction                 = "Stop"
            }
            $SignSSHHostKeyResult = Sign-SSHHostPublicKey @SignSSHHostKeySplatParams
            if (!$SignSSHHostKeyResult) {throw "There was a problem with the Sign-SSHHostPublicKey function!"}
            $Output.Add("SignSSHHostKeyResult",$SignSSHHostKeyResult)
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    # We need to get $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString
    if ($PublicKeyOfCAUsedToSignUserKeysVaultUrl) {
        # Make sure $SiteUrl is a valid Url
        try {
            $UriObject = [uri]$PublicKeyOfCAUsedToSignUserKeysVaultUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignUserKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        try {
            $PublicKeyOfCAUsedToSignUserKeysAsString = $(Invoke-WebRequest -Uri $PublicKeyOfCAUsedToSignUserKeysVaultUrl).Content.Trim()
            if (!$PublicKeyOfCAUsedToSignUserKeysAsString) {throw "Invoke-WebRequest failed to get the CA's Public Key from Vault! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    if ($PublicKeyOfCAUsedToSignHostKeysVaultUrl) {
        # Make sure $SiteUrl is a valid Url
        try {
            $UriObject = [uri]$PublicKeyOfCAUsedToSignHostKeysVaultUrl
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        if (![bool]$($UriObject.Scheme -match "http")) {
            Write-Error "'$PublicKeyOfCAUsedToSignHostKeysVaultUrl' does not appear to be a URL! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }

        try {
            $PublicKeyOfCAUsedToSignHostKeysAsString = $(Invoke-WebRequest -Uri $PublicKeyOfCAUsedToSignHostKeysVaultUrl).Content.Trim()
            if (!$PublicKeyOfCAUsedToSignHostKeysAsString) {throw "Invoke-WebRequest failed to get the CA's Public Key from Vault! Halting!"}
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    if ($PublicKeyOfCAUsedToSignUserKeysFilePath) {
        if (! $(Test-Path $PublicKeyOfCAUsedToSignUserKeysFilePath)) {
            Write-Error "The path '$PublicKeyOfCAUsedToSignUserKeysFilePath' was not found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
        
        $PublicKeyOfCAUsedToSignUserKeysAsString = Get-Content $PublicKeyOfCAUsedToSignUserKeysFilePath
    }
    if ($PublicKeyOfCAUsedToSignHostKeysFilePath) {
        if (! $(Test-Path $PublicKeyOfCAUsedToSignHostKeysFilePath)) {
            Write-Error "The path '$PublicKeyOfCAUsedToSignHostKeysFilePath' was not found! Halting!"
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
        
        $PublicKeyOfCAUsedToSignHostKeysAsString = Get-Content $PublicKeyOfCAUsedToSignHostKeysFilePath
    }

    # Now we have $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString
    # Need to make sure these strings exist in dedicated files under $sshdir as well as in 
    # $sshdir/authorized_keys and $sshdir/ssh_known_hosts

    # Before adding these CA Public Keys to $sshdir/authorized_keys, if there's already an existing
    # $sshdir/authorized_keys, archive it in a folder called $sshdir/Archive so that we can revert if necessary
    if (Test-Path "$sshdir/authorized_keys") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/authorized_keys" -Destination "$sshdir/Archive" -Force
    }
    # Before adding these CA Public Keys to $sshdir/ssh_known_hosts, if there's already an existing
    # $sshdir/ssh_known_hosts, archive it in a folder called $sshdir/Archive so that we can revert if necessary
    if (Test-Path "$sshdir/ssh_known_hosts") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/ssh_known_hosts" -Destination "$sshdir/Archive" -Force
    }

    # Add the CA Public Certs to $sshdir/authorized_keys in their appropriate formats
    $ContentToAddToAuthKeys = @(
        "ssh-rsa-cert-v01@openssh.com " + $PublicKeyOfCAUsedToSignUserKeysAsString
        "ssh-rsa-cert-v01@openssh.com " + $PublicKeyOfCAUsedToSignHostKeysAsString
    )
    $ContentToAddToAuthKeysString = $ContentToAddToAuthKeys -join "`n"
    Add-Content -Path "$sshdir/authorized_keys" -Value $ContentToAddToAuthKeysString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/authorized_keys"))

    # Add the CA Public Certs to $sshdir/ssh_known_hosts in their appropriate formats
    $ContentToAddToKnownHosts = @(
        "@cert-authority * " + $PublicKeyOfCAUsedToSignUserKeysAsString
        "@cert-authority * " + $PublicKeyOfCAUsedToSignHostKeysAsString
    )
    $ContentToAddToKnownHostsString = $ContentToAddToKnownHosts -join "`n"
    Add-Content -Path $sshdir/ssh_known_hosts -Value $ContentToAddToKnownHostsString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/ssh_known_hosts"))

    # Make sure $PublicKeyOfCAUsedToSignUserKeysAsString and $PublicKeyOfCAUsedToSignHostKeysAsString are written
    # to their own dedicated files under $sshdir
    
    # If $PublicKeyOfCAUsedToSignUserKeysFilePath or $PublicKeyOfCAUsedToSignHostKeysFilePath were actually provided
    # maintain the same file name when writing to $sshdir
    if ($PSBoundParameters.ContainsKey('PublicKeyOfCAUsedToSignUserKeysFilePath')) {
        $UserCAPubKeyFileName = $PublicKeyOfCAUsedToSignUserKeysFilePath | Split-Path -Leaf
    }
    else {
        $UserCAPubKeyFileName = "ca_pub_key_of_client_signer.pub"
    }
    if ($PSBoundParameters.ContainsKey('PublicKeyOfCAUsedToSignHostKeysFilePath')) {
        $HostCAPubKeyFileName = $PublicKeyOfCAUsedToSignHostKeysFilePath | Split-Path -Leaf
    }
    else {
        $HostCAPubKeyFileName = "ca_pub_key_of_host_signer.pub"
    }

    if (Test-Path "$sshdir/$UserCAPubKeyFileName") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/$UserCAPubKeyFileName" -Destination "$sshdir/Archive" -Force
    }
    if (Test-Path "$sshdir/$HostCAPubKeyFileName") {
        if (!$(Test-Path "$sshdir/Archive")) {
            $null = New-Item -ItemType Directory -Path "$sshdir/Archive" -Force
        }
        Move-Item -Path "$sshdir/$HostCAPubKeyFileName" -Destination "$sshdir/Archive" -Force
    }

    Set-Content -Path "$sshdir/$UserCAPubKeyFileName" -Value $PublicKeyOfCAUsedToSignUserKeysAsString
    Set-Content -Path "$sshdir/$HostCAPubKeyFileName" -Value $PublicKeyOfCAUsedToSignHostKeysAsString
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/$UserCAPubKeyFileName"))
    $null = $FilesUpdated.Add($(Get-Item "$sshdir/$HostCAPubKeyFileName"))
    

    # Next, we need to generate some content for $sshdir/authorized_principals

    # IMPORTANT NOTE: The Generate-AuthorizedPrincipalsFile will only ADD users to the $sshdir/authorized_principals
    # file (if they're not already in there). It WILL NOT delete or otherwise overwrite existing users in
    # $sshdir/authorized_principals
    $AuthPrincSplatParams = @{
        ErrorAction     = "Stop"
    }
    if ($(!$AuthorizedPrincipalsUserGroup -and !$AuthorizedUserPrincipals) -or
    $AuthorizedPrincipalsUserGroup -contains "AllUsers" -or
    $($AuthorizedPrincipalsUserGroup -contains "LocalAdmins" -and $AuthorizedPrincipalsUserGroup -contains "LocalUsers" -and
    $AuthorizedPrincipalsUserGroup -contains "DomainAdmins" -and $AuthorizedPrincipalsUserGroup -contains "DomainAdmins")
    ) {
        $AuthPrincSplatParams.Add("UserGroupToAdd",@("AllUsers"))
    }
    else {
        if ($AuthorizedPrincipalsUserGroup) {
            $AuthPrincSplatParams.Add("UserGroupToAdd",$AuthorizedPrincipalsUserGroup)
        }
        if ($AuthorizedUserPrincipals) {
            $AuthPrincSplatParams.Add("UsersToAdd",$AuthorizedUserPrincipals)
        }
    }

    try {
        $AuthorizedPrincipalsFile = Generate-AuthorizedPrincipalsFile @AuthPrincSplatParams
        if (!$AuthorizedPrincipalsFile) {throw "There was a problem with the Generate-AuthorizedPrincipalsFile function! Halting!"}

        $null = $FilesUpdated.Add($(Get-Item "$sshdir/authorized_principals"))        
    }
    catch {
        Write-Error $_
        $global:FunctionResult = "1"
        if ($Output.Count -gt 0) {[pscustomobject]$Output}
        return
    }

    # Now we need to fix permissions for $sshdir/authroized_principals...
    if ($PSVersionTable.PSEdition -eq "Core") {
        Invoke-WinCommand -ComputerName localhost -ScriptBlock {
            $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$($args[0])/authorized_principals"
            $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
            $SecurityDescriptor | Clear-NTFSAccess
            $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
            $SecurityDescriptor | Set-NTFSSecurityDescriptor
        } -ArgumentList $sshdir
    }
    else {
        $SecurityDescriptor = Get-NTFSSecurityDescriptor -Path "$sshdir/authorized_principals"
        $SecurityDescriptor | Disable-NTFSAccessInheritance -RemoveInheritedAccessRules
        $SecurityDescriptor | Clear-NTFSAccess
        $SecurityDescriptor | Add-NTFSAccess -Account "NT AUTHORITY\SYSTEM" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Add-NTFSAccess -Account "Administrators" -AccessRights "FullControl" -AppliesTo ThisFolderSubfoldersAndFiles
        $SecurityDescriptor | Set-NTFSSecurityDescriptor
    }

    # Now that we have set content for $PublicKeyOfCAUsedToSignUserKeysFilePath, $sshdir/authorized_principals, and
    # $sshdir/authorized_keys, we need to update sshd_config to reference these files

    $PubKeyOfCAUserKeysFilePathForwardSlashes = "$sshdir\$UserCAPubKeyFileName" -replace '\\','/'
    $TrustedUserCAKeysOptionLine = "TrustedUserCAKeys $PubKeyOfCAUserKeysFilePathForwardSlashes"
    # For more information about authorized_principals content (specifically about setting specific commands and roles
    # for certain users), see: https://framkant.org/2017/07/scalable-access-control-using-openssh-certificates/
    $AuthPrincFilePathForwardSlashes = "$sshdir\authorized_principals" -replace '\\','/'
    $AuthorizedPrincipalsOptionLine = "AuthorizedPrincipalsFile $AuthPrincFilePathForwardSlashes"
    $AuthKeysFilePathForwardSlashes = "$sshdir\authorized_keys" -replace '\\','/'
    $AuthorizedKeysFileOptionLine = "AuthorizedKeysFile $AuthKeysFilePathForwardSlashes"

    [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath

    # Determine if sshd_config already has the 'TrustedUserCAKeys' option active
    $ExistingTrustedUserCAKeysOption = $sshdContent -match "TrustedUserCAKeys" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'AuthorizedPrincipals' option active
    $ExistingAuthorizedPrincipalsFileOption = $sshdContent -match "AuthorizedPrincipalsFile" | Where-Object {$_ -notmatch "#"}

    # Determine if sshd_config already has 'AuthorizedKeysFile' option active
    $ExistingAuthorizedKeysFileOption = $sshdContent -match "AuthorizedKeysFile" | Where-Object {$_ -notmatch "#"}
    
    if (!$ExistingTrustedUserCAKeysOption) {
        # If sshd_config already has the 'Match User' option available, don't touch it, else add it with ForceCommand
        try {
            Add-Content -Value $TrustedUserCAKeysOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingTrustedUserCAKeysOption -ne $TrustedUserCAKeysOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingTrustedUserCAKeysOption),"$TrustedUserCAKeysOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'TrustedUserCAKeys' option is already active in the the sshd_config file. No changes made."
        }
    }

    if (!$ExistingAuthorizedPrincipalsFileOption) {
        try {
            Add-Content -Value $AuthorizedPrincipalsOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingAuthorizedPrincipalsFileOption -ne $AuthorizedPrincipalsOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingAuthorizedPrincipalsFileOption),"$AuthorizedPrincipalsOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'AuthorizedPrincipalsFile' option is already active in the the sshd_config file. No changes made."
        }
    }

    if (!$ExistingAuthorizedKeysFileOption) {
        try {
            Add-Content -Value $AuthorizedKeysFileOptionLine -Path $sshdConfigPath
            $SSHDConfigContentChanged = $True
            [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }
    else {
        if ($ExistingAuthorizedKeysFileOption -ne $AuthorizedKeysFileOptionLine) {
            $UpdatedSSHDConfig = $sshdContent -replace [regex]::Escape($ExistingAuthorizedKeysFileOption),"$AuthorizedKeysFileOptionLine"

            try {
                Set-Content -Value $UpdatedSSHDConfig -Path $sshdConfigPath
                $SSHDConfigContentChanged = $True
                [System.Collections.ArrayList]$sshdContent = Get-Content $sshdConfigPath
            }
            catch {
                Write-Error $_
                $global:FunctionResult = "1"
                if ($Output.Count -gt 0) {[pscustomobject]$Output}
                return
            }
        }
        else {
            Write-Warning "The specified 'AuthorizedKeysFile' option is already active in the the sshd_config file. No changes made."
        }
    }

    if ($SSHDConfigContentChanged) {
        $null = $FilesUpdated.Add($(Get-Item $sshdConfigPath))
        
        try {
            Restart-Service sshd -ErrorAction Stop
        }
        catch {
            Write-Error $_
            $global:FunctionResult = "1"
            if ($Output.Count -gt 0) {[pscustomobject]$Output}
            return
        }
    }

    [pscustomobject]$Output
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUcvjyDcoaHAlC6nmsULMG1RZv
# qQigggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
# 9w0BAQsFADAwMQwwCgYDVQQGEwNMQUIxDTALBgNVBAoTBFpFUk8xETAPBgNVBAMT
# CFplcm9EQzAxMB4XDTE3MDkyMDIxMDM1OFoXDTE5MDkyMDIxMTM1OFowPTETMBEG
# CgmSJomT8ixkARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMT
# B1plcm9TQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCwqv+ROc1
# bpJmKx+8rPUUfT3kPSUYeDxY8GXU2RrWcL5TSZ6AVJsvNpj+7d94OEmPZate7h4d
# gJnhCSyh2/3v0BHBdgPzLcveLpxPiSWpTnqSWlLUW2NMFRRojZRscdA+e+9QotOB
# aZmnLDrlePQe5W7S1CxbVu+W0H5/ukte5h6gsKa0ktNJ6X9nOPiGBMn1LcZV/Ksl
# lUyuTc7KKYydYjbSSv2rQ4qmZCQHqxyNWVub1IiEP7ClqCYqeCdsTtfw4Y3WKxDI
# JaPmWzlHNs0nkEjvnAJhsRdLFbvY5C2KJIenxR0gA79U8Xd6+cZanrBUNbUC8GCN
# wYkYp4A4Jx+9AgMBAAGjggEqMIIBJjASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsG
# AQQBgjcVAgQWBBQ/0jsn2LS8aZiDw0omqt9+KWpj3DAdBgNVHQ4EFgQUicLX4r2C
# Kn0Zf5NYut8n7bkyhf4wGQYJKwYBBAGCNxQCBAweCgBTAHUAYgBDAEEwDgYDVR0P
# AQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHwYDVR0jBBgwFoAUdpW6phL2RQNF
# 7AZBgQV4tgr7OE0wMQYDVR0fBCowKDAmoCSgIoYgaHR0cDovL3BraS9jZXJ0ZGF0
# YS9aZXJvREMwMS5jcmwwPAYIKwYBBQUHAQEEMDAuMCwGCCsGAQUFBzAChiBodHRw
# Oi8vcGtpL2NlcnRkYXRhL1plcm9EQzAxLmNydDANBgkqhkiG9w0BAQsFAAOCAQEA
# tyX7aHk8vUM2WTQKINtrHKJJi29HaxhPaHrNZ0c32H70YZoFFaryM0GMowEaDbj0
# a3ShBuQWfW7bD7Z4DmNc5Q6cp7JeDKSZHwe5JWFGrl7DlSFSab/+a0GQgtG05dXW
# YVQsrwgfTDRXkmpLQxvSxAbxKiGrnuS+kaYmzRVDYWSZHwHFNgxeZ/La9/8FdCir
# MXdJEAGzG+9TwO9JvJSyoGTzu7n93IQp6QteRlaYVemd5/fYqBhtskk1zDiv9edk
# mHHpRWf9Xo94ZPEy7BqmDuixm4LdmmzIcFWqGGMo51hvzz0EaE8K5HuNvNaUB/hq
# MTOIB5145K8bFOoKHO4LkTCCBc8wggS3oAMCAQICE1gAAAH5oOvjAv3166MAAQAA
# AfkwDQYJKoZIhvcNAQELBQAwPTETMBEGCgmSJomT8ixkARkWA0xBQjEUMBIGCgmS
# JomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EwHhcNMTcwOTIwMjE0MTIy
# WhcNMTkwOTIwMjExMzU4WjBpMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExFTAT
# BgNVBAcTDFBoaWxhZGVscGhpYTEVMBMGA1UEChMMRGlNYWdnaW8gSW5jMQswCQYD
# VQQLEwJJVDESMBAGA1UEAxMJWmVyb0NvZGUyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAxX0+4yas6xfiaNVVVZJB2aRK+gS3iEMLx8wMF3kLJYLJyR+l
# rcGF/x3gMxcvkKJQouLuChjh2+i7Ra1aO37ch3X3KDMZIoWrSzbbvqdBlwax7Gsm
# BdLH9HZimSMCVgux0IfkClvnOlrc7Wpv1jqgvseRku5YKnNm1JD+91JDp/hBWRxR
# 3Qg2OR667FJd1Q/5FWwAdrzoQbFUuvAyeVl7TNW0n1XUHRgq9+ZYawb+fxl1ruTj
# 3MoktaLVzFKWqeHPKvgUTTnXvEbLh9RzX1eApZfTJmnUjBcl1tCQbSzLYkfJlJO6
# eRUHZwojUK+TkidfklU2SpgvyJm2DhCtssFWiQIDAQABo4ICmjCCApYwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBS5d2bhatXq
# eUDFo9KltQWHthbPKzAfBgNVHSMEGDAWgBSJwtfivYIqfRl/k1i63yftuTKF/jCB
# 6QYDVR0fBIHhMIHeMIHboIHYoIHVhoGubGRhcDovLy9DTj1aZXJvU0NBKDEpLENO
# PVplcm9TQ0EsQ049Q0RQLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNl
# cnZpY2VzLENOPUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y2VydGlmaWNh
# dGVSZXZvY2F0aW9uTGlzdD9iYXNlP29iamVjdENsYXNzPWNSTERpc3RyaWJ1dGlv
# blBvaW50hiJodHRwOi8vcGtpL2NlcnRkYXRhL1plcm9TQ0EoMSkuY3JsMIHmBggr
# BgEFBQcBAQSB2TCB1jCBowYIKwYBBQUHMAKGgZZsZGFwOi8vL0NOPVplcm9TQ0Es
# Q049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENO
# PUNvbmZpZ3VyYXRpb24sREM9emVybyxEQz1sYWI/Y0FDZXJ0aWZpY2F0ZT9iYXNl
# P29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwLgYIKwYBBQUHMAKG
# Imh0dHA6Ly9wa2kvY2VydGRhdGEvWmVyb1NDQSgxKS5jcnQwPQYJKwYBBAGCNxUH
# BDAwLgYmKwYBBAGCNxUIg7j0P4Sb8nmD8Y84g7C3MobRzXiBJ6HzzB+P2VUCAWQC
# AQUwGwYJKwYBBAGCNxUKBA4wDDAKBggrBgEFBQcDAzANBgkqhkiG9w0BAQsFAAOC
# AQEAszRRF+YTPhd9UbkJZy/pZQIqTjpXLpbhxWzs1ECTwtIbJPiI4dhAVAjrzkGj
# DyXYWmpnNsyk19qE82AX75G9FLESfHbtesUXnrhbnsov4/D/qmXk/1KD9CE0lQHF
# Lu2DvOsdf2mp2pjdeBgKMRuy4cZ0VCc/myO7uy7dq0CvVdXRsQC6Fqtr7yob9NbE
# OdUYDBAGrt5ZAkw5YeL8H9E3JLGXtE7ir3ksT6Ki1mont2epJfHkO5JkmOI6XVtg
# anuOGbo62885BOiXLu5+H2Fg+8ueTP40zFhfLh3e3Kj6Lm/NdovqqTBAsk04tFW9
# Hp4gWfVc0gTDwok3rHOrfIY35TGCAfUwggHxAgEBMFQwPTETMBEGCgmSJomT8ixk
# ARkWA0xBQjEUMBIGCgmSJomT8ixkARkWBFpFUk8xEDAOBgNVBAMTB1plcm9TQ0EC
# E1gAAAH5oOvjAv3166MAAQAAAfkwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwx
# CjAIoAKAAKECgAAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGC
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFSQuZEtj8Hc57L0
# MgjTpL6KJgOSMA0GCSqGSIb3DQEBAQUABIIBAHl8Shoxvs4orsbqv7jNKC9pboEE
# UPmPlqtiRZU+SP8YEGC876DKqJRh31scYZrgl8ij3O8NhZ7Y2MVbq+OlN2oSqNPd
# ijgjdUX5J53ZIGZcD8sD0KXGlggMnI1mmzMSBnLDgYoAodnoj9OCqez4xl3edKs7
# hpspGHeJ8L+vtt0smmjLGbefBF4KVNltIlqLSUzh0kB0vRamZaIaL0NNyO3WcJxD
# TGRHk5iimQ7Q5xfRT0iWf6EdbQW4H/oEDpq0p6nLeNvV/k0U3cWVH32RlEYrIiGz
# 8KebcjkPLGLWmB+wbl+gdc5yUz2DPiKum+dSqMqt6r+JJxj7UNWWa55YTNg=
# SIG # End signature block
