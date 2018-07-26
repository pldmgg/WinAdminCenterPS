<#
    .SYNOPSIS
        Tests if a module contains a class resource.

    .PARAMETER ModulePath
        The path to the module to test.
#>
function Test-ModuleContainsClassResource
{
    [OutputType([Boolean])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $ModulePath
    )

    $psm1Files = Get-Psm1FileList -FilePath $ModulePath

    foreach ($psm1File in $psm1Files)
    {
        if (Test-FileContainsClassResource -FilePath $psm1File.FullName)
        {
            return $true
        }
    }

    return $false
}

<#
    .SYNOPSIS
        Retrieves all .psm1 files under the given file path.

    .PARAMETER FilePath
        The root file path to gather the .psm1 files from.
#>
function Get-Psm1FileList
{
    [OutputType([Object[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $FilePath
    )

    return Get-ChildItem -Path $FilePath -Filter '*.psm1' -File -Recurse
}

<#
    .SYNOPSIS
        Retrieves the parse errors for the given file.

    .PARAMETER FilePath
        The path to the file to get parse errors for.
#>
function Get-FileParseErrors
{
    [OutputType([System.Management.Automation.Language.ParseError[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [String]
        $FilePath
    )

    $parseErrors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref] $null, [ref] $parseErrors)

    return $parseErrors
}

<#
    .SYNOPSIS
        Retrieves all text files under the given root file path.

    .PARAMETER Root
        The root file path under which to retrieve all text files.

    .NOTES
        Retrieves all files with the '.gitignore', '.gitattributes', '.ps1', '.psm1', '.psd1',
        '.json', '.xml', '.cmd', or '.mof' file extensions.
#>
function Get-TextFilesList
{
    [OutputType([System.IO.FileInfo[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Root
    )

    $textFileExtensions = @('.gitignore', '.gitattributes', '.ps1', '.psm1', '.psd1', '.json', '.xml', '.cmd', '.mof','.md','.js','.yml')

    return Get-ChildItem -Path $Root -File -Recurse | Where-Object { $textFileExtensions -contains $_.Extension }
}

function ConvertTo-SpaceIndentation
{
    [CmdletBinding()]
    [OutputType([void])]
    param(
        [Parameter(ValueFromPipeline=$true, Mandatory=$true)]
        [System.IO.FileInfo]$fileInfo
    )

    process 
    {
        $content = (Get-Content -Raw -Path $fileInfo.FullName) -replace "`t",' '
        [System.IO.File]::WriteAllText($fileInfo.FullName, $content)
    }
}

<#
    .SYNOPSIS
        Tests if a file is encoded in Unicode.

    .PARAMETER FileInfo
        The file to test.
#>
function Test-FileInUnicode {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(ValueFromPipeline = $true, Mandatory = $true)]
        [System.IO.FileInfo]$fileInfo
    )

    process {
        $path = $fileInfo.FullName
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $zeroBytes = @($bytes -eq 0)
        return [bool]$zeroBytes.Length

    }
}

<#
    .SYNOPSIS
        Downloads and installs a module from PowerShellGallery using
        Nuget.

    .PARAMETER ModuleName
        Name of the module to install

    .PARAMETER DestinationPath
        Path where module should be installed
#>
function Install-ModuleFromPowerShellGallery
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [String]
        $DestinationPath
    )

    $nugetPath = 'nuget.exe'

    # Can't assume nuget.exe is available - look for it in Path
    if ($null -eq (Get-Command -Name $nugetPath -ErrorAction 'SilentlyContinue'))
    {
        # Is it in temp folder?
        $tempNugetPath = Join-Path -Path $env:temp -ChildPath $nugetPath

        if (-not (Test-Path -Path $tempNugetPath))
        {
            # Nuget.exe can't be found - download it to temp folder
            $nugetDownloadURL = 'http://nuget.org/nuget.exe'

            Invoke-WebRequest -Uri $nugetDownloadURL -OutFile $tempNugetPath
            Write-Verbose -Message "nuget.exe downloaded at $tempNugetPath"

            $nugetPath = $tempNugetPath
        }
        else
        {
            Write-Verbose -Message "Using Nuget.exe found at $tempNugetPath"
        }
    }

    $moduleOutputDirectory = "$(Split-Path -Path $DestinationPath -Parent)\"

    $nugetSource = 'https://www.powershellgallery.com/api/v2'
    # Use Nuget.exe to install the module
    $null = & $nugetPath @( `
        'install', $ModuleName, `
        '-source', $nugetSource, `
        '-outputDirectory', $moduleOutputDirectory, `
        '-ExcludeVersion' `
        )

    if ($LASTEXITCODE -ne 0)
    {
        throw "Installation of module $ModuleName using Nuget failed with exit code $LASTEXITCODE."
    }

    Write-Verbose -Message "The module $ModuleName was installed using Nuget."
}

<#
    .SYNOPSIS
        Imports the PS Script Analyzer module.
        Installs the module from the PowerShell Gallery if it is not already installed.
#>
function Import-PSScriptAnalyzer
{
    [CmdletBinding()]
    param ()

    $psScriptAnalyzerModule = Get-Module -Name 'PSScriptAnalyzer' -ListAvailable

    if ($null -eq $psScriptAnalyzerModule)
    {
        Write-Verbose -Message 'Installing PSScriptAnalyzer from the PowerShell Gallery'
        $userProfilePSModulePathItem = Get-UserProfilePSModulePathItem
        $psScriptAnalyzerModulePath = Join-Path -Path $userProfilePSModulePathItem -ChildPath PSScriptAnalyzer
        Install-ModuleFromPowerShellGallery -ModuleName 'PSScriptAnalyzer' -DestinationPath $psScriptAnalyzerModulePath
    }

    $psScriptAnalyzerModule = Get-Module -Name 'PSScriptAnalyzer' -ListAvailable

    <#
        When using custom rules in PSSA the Get-Help cmdlet gets
        called by PSSA. This causes a warning to be thrown in AppVeyor.
        This warning does not cause a failure or error, but causes
        additional bloat to the analyzer output. To suppress this
        the registry key
        HKLM:\Software\Microsoft\PowerShell\DisablePromptToUpdateHelp
        should be set to 1 when running in AppVeyor.

        See this line from PSSA in GetExternalRule() method for more
        information:
        https://github.com/PowerShell/PSScriptAnalyzer/blob/development/Engine/ScriptAnalyzer.cs#L1120
    #>
    if ($env:APPVEYOR -eq $true)
    {
        Set-ItemProperty -Path HKLM:\Software\Microsoft\PowerShell -Name DisablePromptToUpdateHelp -Value 1
    }

    Import-Module -Name $psScriptAnalyzerModule
}

<#
    .SYNOPSIS
        Retrieves the list of suppressed PSSA rules in the file at the given path.

    .PARAMETER FilePath
        The path to the file to retrieve the suppressed rules of.
#>
function Get-SuppressedPSSARuleNameList
{
    [OutputType([String[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $FilePath
    )

    $suppressedPSSARuleNames = [String[]]@()

    $fileAst = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$null, [ref]$null)

    # Overall file attributes
    $attributeAsts = $fileAst.FindAll({$args[0] -is [System.Management.Automation.Language.AttributeAst]}, $true)

    foreach ($attributeAst in $attributeAsts)
    {
        if ([System.Diagnostics.CodeAnalysis.SuppressMessageAttribute].FullName.ToLower().Contains($attributeAst.TypeName.FullName.ToLower()))
        {
            $suppressedPSSARuleNames += $attributeAst.PositionalArguments.Extent.Text
        }
    }

    return $suppressedPSSARuleNames
}

<#
    .SYNOPSIS
        Gets the current Pester Describe block name
#>
function Get-PesterDescribeName
{

    return Get-CommandNameParameterValue -Command 'Describe'
}

<#
    .SYNOPSIS
        Gets the opt-in status of the current pester Describe
        block. Writes a warning if the test is not opted-in.

    .PARAMETER OptIns
        An array of what is opted-in
#>
function Get-PesterDescribeOptInStatus
{
    param
    (
        [Parameter()]
        [System.String[]]
        $OptIns
    )

    $describeName = Get-PesterDescribeName
    $optIn = $OptIns -icontains $describeName
    if (-not $optIn)
    {
        $message = @"
Describe $describeName will not fail unless you opt-in.
To opt-in, create a '.MetaTestOptIn.json' at the root
of the repo in the following format:
[
     "$describeName"
]
"@
        Write-Warning -Message $message
    }

    return $optIn
}

<#
    .SYNOPSIS
        Gets the opt-in status of an option with the specified name. Writes
        a warning if the test is not opted-in.

    .PARAMETER OptIns
        An array of what is opted-in.

    .PARAMETER Name
        The name of the opt-in option to check the status of.
#>
function Get-OptInStatus
{
    param
    (
        [Parameter()]
        [System.String[]]
        $OptIns,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Name
    )

    $optIn = $OptIns -icontains $Name
    if (-not $optIn)
    {
        $message = @"
$Name will not fail unless you opt-in.
To opt-in, create a '.MetaTestOptIn.json' at the root
of the repo in the following format:
[
     "$Name"
]
"@
        Write-Warning -Message $message
    }

    return $optIn
}

<#
    .SYNOPSIS
        Gets the value of the Name parameter for the specified command in the stack.

    .PARAMETER Command
        The name of the command to find the Name parameter for.
#>
function Get-CommandNameParameterValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Command
    )

    $commandStackItem = (Get-PSCallStack).Where{ $_.Command -eq $Command }
    $commandArgumentNameValues = $commandStackItem.Arguments.TrimStart('{',' ').TrimEnd('}',' ') -split '\s*,\s*'
    $nameParameterValue = ($commandArgumentNameValues.Where{ $_ -like 'name=*' } -split '=')[-1]
    return $nameParameterValue
}

<#
    .SYNOPSIS
        Returns first the item in $env:PSModulePath that matches the given Prefix ($env:PSModulePath is list of semicolon-separated items).
        If no items are found, it reports an error.
    .PARAMETER Prefix
        Path prefix to look for.
    .NOTES
        If there are multiple matching items, the function returns the first item that occurs in the module path; this matches the lookup
        behavior of PowerSHell, which looks at the items in the module path in order of occurrence.
    .EXAMPLE
        If $env:PSModulePath is
            C:\Program Files\WindowsPowerShell\Modules;C:\Users\foo\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        then
            Get-PSModulePathItem C:\Users
        will return
            C:\Users\foo\Documents\WindowsPowerShell\Modules
#>
function Get-PSModulePathItem
{
    param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [System.String]
        $Prefix
    )

    $item = $env:PSModulePath.Split(';') |
        Where-Object -FilterScript { $_ -like "$Prefix*" } |
        Select-Object -First 1

    if (-not $item)
    {
        Write-Error -Message "Cannot find the requested item in the PowerShell module path.`n`$env:PSModulePath = $env:PSModulePath"
    }

    return $item
}

<#
    .SYNOPSIS
        Returns the first item in $env:PSModulePath that is a path under $env:USERPROFILE.
        If no items are found, it reports an error.
    .EXAMPLE
        If $env:PSModulePath is
            C:\Program Files\WindowsPowerShell\Modules;C:\Users\foo\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        and the current user is 'foo', then
            Get-UserProfilePSModulePathItem
        will return
            C:\Users\foo\Documents\WindowsPowerShell\Modules
#>
function Get-UserProfilePSModulePathItem {
    param()

    return Get-PSModulePathItem -Prefix $env:USERPROFILE
}

<#
    .SYNOPSIS
        Returns the first item in $env:PSModulePath that is a path under $env:USERPROFILE.
        If no items are found, it reports an error.
    .EXAMPLE
        If $env:PSModulePath is
            C:\Program Files\WindowsPowerShell\Modules;C:\Users\foo\Documents\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules
        then
            Get-PSHomePSModulePathItem
        will return
            C:\Windows\system32\WindowsPowerShell\v1.0\Modules
#>
function Get-PSHomePSModulePathItem {
    param()

    return Get-PSModulePathItem -Prefix $global:PSHOME
}

<#
    .SYNOPSIS
        Tests if a file contains Byte Order Mark (BOM).

    .PARAMETER FilePath
        The file path to evaluate.
#>
function Test-FileHasByteOrderMark
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath
    )

    # This reads the first three bytes of the first row.
    $firstThreeBytes = Get-Content -Path $FilePath -Encoding Byte -ReadCount 3 -TotalCount 3

    # Check for the correct byte order (239,187,191) which equal the Byte Order Mark (BOM).
    return ($firstThreeBytes[0] -eq 239 `
        -and $firstThreeBytes[1] -eq 187 `
        -and $firstThreeBytes[2] -eq 191)
}

<#
    .SYNOPSIS
        This returns a string containing the relative path from the module root.

    .PARAMETER FilePath
        The file path to remove the module root path from.

    .PARAMETER ModuleRootFilePath
        The root path to remove from the file path.
#>
function Get-RelativePathFromModuleRoot
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $FilePath,

        [Parameter(Mandatory = $true)]
        [System.String]
        $ModuleRootFilePath
    )

    <#
        Removing the module root path from the file path so that the path
        doesn't get so long in the Pester output.
    #>
    return ($FilePath -replace [Regex]::Escape($ModuleRootFilePath),'').Trim('\')
}

<#
    .SYNOPSIS
        Installs dependent modules in the user scope, if not already available
        and only if run on an AppVeyor build worker. If not run on a AppVeyor
        build worker, it will output a warning saying that the users must
        install the correct module to be able to run the test.

    .PARAMETER Module
        An array of hash tables containing one or more dependent modules that
        should be installed. The correct array is returned by the helper
        function Get-ResourceModulesInConfiguration.

        Hash table should be in this format. Where property Name is mandatory
        and property Version is optional.

        @{
            Name    = 'xStorage'
            [Version = '3.2.0.0']
        }
#>
function Install-DependentModule
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable[]]
        $Module
    )

    # Check any additional modules required are installed
    foreach ($requiredModule in $Module)
    {
        $getModuleParameters = @{
            Name = $requiredModule.Name
            ListAvailable = $true
            ErrorAction = 'SilentlyContinue'
        }

        if ($requiredModule.ContainsKey('Version'))
        {
            $requiredModuleExist = `
                Get-Module @getModuleParameters |
                    Where-Object -FilterScript {
                        $_.Version -eq $requiredModule.Version
                    }
        }
        else
        {
            $requiredModuleExist = Get-Module @getModuleParameters
        }

        if (-not ($requiredModuleExist))
        {
            # The required module is missing from this machine
            if ($requiredModule.ContainsKey('Version'))
            {
                $requiredModuleName = ('{0} version {1}' -f $requiredModule.Name, $requiredModule.Version)
            }
            else
            {
                $requiredModuleName = ('{0}' -f $requiredModule.Name)
            }

            if ($env:APPVEYOR -eq $true)
            {
                <#
                    Tests are running in AppVeyor so just install the module.
                    If not installed by using Force then the error message
                    "User declined to install untrusted module (<module name>)."
                    is thrown
                #>
                $installModuleParameters = @{
                    Name  = $requiredModule.Name
                    Force = $true
                }

                if ($requiredModule.ContainsKey('Version'))
                {
                    $installModuleParameters['RequiredVersion'] = $requiredModule.Version
                }

                Write-Verbose -Message "Installing module $requiredModuleName required to compile a configuration." -Verbose
                try
                {
                    Install-Module @installModuleParameters -Scope CurrentUser
                }
                catch
                {
                    throw "An error occurred installing the required module $($requiredModuleName) : $_"
                }
            }
            else
            {
                # Warn the user that the test fill fail
                Write-Warning -Message ("To be able to compile a configuration the resource module $requiredModuleName " + `
                    'is required but it is not installed on this computer. ' + `
                    'The test that is dependent on this module will fail until the required module is installed. ' + `
                    'Please install it from the PowerShell Gallery to enable these tests to pass.')
            } # if
        } # if
    } # foreach
}

<#
    .SYNOPSIS
        The is a wrapper to set $env:PSModulePath both in current session and
        machine wide.
        This is needed to be able to mock the function in the unit tests.

    .PARAMETER Path
        A string with all the paths separated by semi-colons.

    .PARAMETER Machine
        If set the PSModulePath will be changed machine wide. If not set, only
        the current session will be changed.

    .EXAMPLE
        Set-PSModulePath -Path '<Path 1>;<Path 2>'

    .EXAMPLE
        Set-PSModulePath -Path '<Path 1>;<Path 2>' -Machine
#>
function Set-PSModulePath
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter()]
        [Switch]
        $Machine
    )

    if ($Machine.IsPresent)
    {
        [System.Environment]::SetEnvironmentVariable('PSModulePath', $Path, [System.EnvironmentVariableTarget]::Machine)
    }
    else
    {
        $env:PSModulePath = $Path
    }
}

<#
    .SYNOPSIS
        Writes a message to the console in a standard format.

    .PARAMETER Message
        The message to write to the console.

    .PARAMETER ForegroundColor
        The text color to use when writing the message to the console. Defaults
        to 'Yellow'.
#>
function Write-Info
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, Position=0)]
        [System.String]
        $Message,

        [Parameter()]
        [System.String]
        $ForegroundColor = 'Yellow'
    )

    Write-Host -ForegroundColor $ForegroundColor -Object "[Build Info] [UTC $([System.DateTime]::UtcNow)] $message"
}

<#
    .SYNOPSIS
        Retrieves the localized string data based on the machine's culture.
        Falls back to en-US strings if the machine's culture is not supported.

    .PARAMETER ModuleName
        The name of the module as it appears before '.strings.psd1' of the localized string file.
        For example:
            For module: DscResource.Container

    .PARAMETER ModuleRoot
        The module root path where to expect to find the culture folder.
#>
function Get-LocalizedData
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleRoot
    )

    $localizedStringFileLocation = Join-Path -Path $ModuleRoot -ChildPath $PSUICulture

    if (-not (Test-Path -Path $localizedStringFileLocation))
    {
        # Fallback to en-US
        $localizedStringFileLocation = Join-Path -Path $ModuleRoot -ChildPath 'en-US'
    }

    Import-LocalizedData `
        -BindingVariable 'localizedData' `
        -FileName "$ModuleName.strings.psd1" `
        -BaseDirectory $localizedStringFileLocation

    return $localizedData
}

<#
Export-ModuleMember -Function @(
    'Install-ModuleFromPowerShellGallery'
    'Test-ModuleContainsClassResource'
    'Get-Psm1FileList'
    'Get-FileParseErrors'
    'Get-TextFilesList'
    'Test-FileInUnicode'
    'Import-PSScriptAnalyzer'
    'Get-SuppressedPSSARuleNameList'
    'Get-PesterDescribeOptInStatus'
    'Get-OptInStatus'
    'Get-UserProfilePSModulePathItem'
    'Get-PSHomePSModulePathItem'
    'Test-FileHasByteOrderMark'
    'Get-RelativePathFromModuleRoot'
    'Get-ResourceModulesInConfiguration'
    'Install-DependentModule'
    'Set-PSModulePath'
    'Write-Info'
    'Get-LocalizedData'
)
#>

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7DoGJ43QnuJfMvvbjsWEuMUo
# mGegggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFFckhmCGJrlnekRK
# gfqihr6ZxdJEMA0GCSqGSIb3DQEBAQUABIIBAC9TULKMmb2yKnlfYNizWikEqMmk
# k/LYEPzi995hNEWKcya62nvIyDN5HmTtLcPYuCc8ez18w7YkeufuyDGwnYL3Nmla
# +Wyi0YYXAilhTn4lX8UVUFIlTRhrITTzWgCJEgDGaZMto+JY1ScYqK4lGciiZg+j
# 7rlMyDITmH9yn+8nzI4SamnnYDf+XdPNEnGuWLEfC8KcvDlTdrqywd2U3m+M1E4M
# YTOMB175/RHVpXGL9F4Q9wGknSZ9ZNGUqK0jAc2TlFFz96FwKW0w18dvwwpYnMpy
# VKC/FFw+WH7VCN8trQNGn87e3ohJvy3xjTCI7MeLDYqIU+DDFo4DAuwGl4U=
# SIG # End signature block
