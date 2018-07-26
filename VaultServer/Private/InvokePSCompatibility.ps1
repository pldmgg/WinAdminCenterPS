function InvokePSCompatibility {
    [CmdletBinding()]
    Param (
        # $InvocationMethod determines if the GetModuleDependencies function scans a file or loaded function
        [Parameter(Mandatory=$False)]
        [string]$InvocationMethod,

        [Parameter(Mandatory=$False)]
        [string[]]$RequiredModules,

        [Parameter(Mandatory=$False)]
        [switch]$InstallModulesNotAvailableLocally
    )

    #region >> Prep

    if ($PSVersionTable.PSEdition -ne "Core" -or
    $($PSVersionTable.PSEdition -ne "Core" -and $PSVersionTable.Platform -ne "Win32NT")) {
        Write-Error "This function is only meant to be used with PowerShell Core on Windows! Halting!"
        $global:FunctionResult = "1"
        return
    }

    AddWinRMTrustLocalHost

    if (!$InvocationMethod) {
        $MyInvParentScope = Get-Variable "MyInvocation" -Scope 1 -ValueOnly
        $PathToFile = $MyInvParentScope.MyCommand.Source
        $FunctionName = $MyInvParentScope.MyCommand.Name

        if ($PathToFile) {
            $InvocationMethod = $PathToFile
        }
        elseif ($FunctionName) {
            $InvocationMethod = $FunctionName
        }
        else {
            Write-Error "Unable to determine MyInvocation Source or Name! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    $AllWindowsPSModulePaths = @(
        "C:\Program Files\WindowsPowerShell\Modules"
        "$HOME\Documents\WindowsPowerShell\Modules"
        "$HOME\Documents\PowerShell\Modules"
        "C:\Program Files\PowerShell\Modules"
        "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\Modules"
    )

    # Determine all current Locally Available Modules
    $AllLocallyAvailableModules = foreach ($ModPath in $AllWindowsPSModulePaths) {
        if (Test-Path $ModPath) {
            $ModuleBases = $(Get-ChildItem -Path $ModPath -Directory).FullName

            foreach ($ModuleBase in $ModuleBases) {
                [pscustomobject]@{
                    ModuleName          = $($ModuleBase | Split-Path -Leaf)
                    ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
                }
            }
        }
    }

    if (![bool]$(Get-Module -ListAvailable WindowsCompatibility)) {
        try {
            Install-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem installing the Windows Compatibility Module! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }
    if (![bool]$(Get-Module WindowsCompatibility)) {
        try {
            Import-Module WindowsCompatibility -ErrorAction Stop
        }
        catch {
            Write-Error $_
            Write-Error "Problem importing the WindowsCompatibility Module! Halting!"
            $global:FunctionResult = "1"
            return
        }
    }

    # Scan Script/Function/Module to get an initial list of Required Locally Available Modules
    try {
        # Below $RequiredLocallyAvailableModules is a PSCustomObject with properties WinPSModuleDependencies
        # and PSCoreModuleDependencies - both of which are [System.Collections.ArrayList]

        # If $InvocationMethod is a file, then GetModuleDependencies can use $PSCommandPath as the value
        # for -PathToScriptFile
        $GetModDepsSplatParams = @{}

        if (![string]::IsNullOrWhitespace($InvocationMethod)) {
            if ($PathToFile -or [bool]$($InvocationMethod -match "\.ps")) {
                if (Test-Path $InvocationMethod) {
                    $GetModDepsSplatParams.Add("PathToScriptFile",$InvocationMethod)
                }
                else {
                    Write-Error "'$InvocationMethod' was not found! Halting!"
                    $global:FunctionResult = "1"
                    return
                }
            }
            else {
                $GetModDepsSplatParams.Add("NameOfLoadedFunction",$InvocationMethod)
            }
        }
        if ($RequiredModules -ne $null) {
            $GetModDepsSplatParams.Add("ExplicitlyNeededModules",$RequiredModules)
        }

        if ($GetModDepsSplatParams.Keys.Count -gt 0) {
            $RequiredLocallyAvailableModulesScan = GetModuleDependencies @GetModDepsSplatParams
        }
    }
    catch {
        Write-Error $_
        Write-Error "Problem with enumerating Module Dependencies using GetModuleDependencies! Halting!"
        $global:FunctionResult = "1"
        return
    }

    #$RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\InitialRequiredLocallyAvailableModules.xml" -Force

    if (!$RequiredLocallyAvailableModulesScan) {
        Write-Host "InvokePSCompatibility reports that no additional modules need to be loaded." -ForegroundColor Green
        return
    }

    if ($RequiredModules) {
        # If, for some reason, the scan conducted by GetModuleDependencies did not determine
        # that $RequiredModules should be included, manually add $RequiredModules to the output
        # (i.e.$RequiredLocallyAvailableModulesScan.WinPSModuleDependencies and/or
        # $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies)
        [System.Collections.ArrayList]$ModulesNotFoundLocally = @()
        foreach ($ModuleName in $RequiredModules) {
            # Determine if $ModuleName is a PSCore or WinPS Module
            [System.Collections.ArrayList]$ModuleInfoArray = @()
            foreach ($ModPath in $AllWindowsPSModulePaths) {
                if (Test-Path "$ModPath\$ModuleName") {
                    $ModuleBase = $(Get-ChildItem -Path $ModPath -Directory -Filter $ModuleName).FullName

                    $ModObj = [pscustomobject]@{
                        ModuleName          = $ModuleName
                        ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
                    }

                    $null = $ModuleInfoArray.Add($ModObj)
                }
            }

            if ($ModuleInfoArray.Count -eq 0) {
                $null = $ModulesNotFoundLocally.Add($ModuleName)
                continue
            }
            
            foreach ($ModObj in $ModuleInfoArray) {
                if ($ModObj.ManifestItem.FullName -match "\\WindowsPowerShell\\") {
                    if ($RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.ManifestFileItem.FullName -notcontains
                    $ModObj.ManifestFileItem.FullName
                    ) {
                        $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($ModObj)
                    }
                }
                if ($ModObj.ManifestItem.FullName -match "\\PowerShell\\") {
                    if ($RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.ManifestFileItem.FullName -notcontains
                    $ModObj.ManifestFileItem.FullName
                    ) {
                        $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($ModObj)
                    }
                }
            }
        }

        # If any of the $RequiredModules are not available on the localhost, install them if that's okay
        [System.Collections.ArrayList]$ModulesSuccessfullyInstalled = @()
        [System.Collections.ArrayList]$ModulesFailedInstall = @()
        if ($ModulesNotFoundLocally.Count -gt 0 -and $InstallModulesNotAvailableLocally) {
            # Since there's currently no way to know if external Modules are actually compatible with PowerShell Core
            # until we try and load them, we just need to install them under both WinPS and PSCore. We will
            # uninstall/remove later once we figure out what actually works.
            foreach ($ModuleName in $ModulesNotFoundLocally) {
                try {
                    if (![bool]$(Get-Module -ListAvailable $ModuleName) -and $InstallModulesNotAvailableLocally) {
                        Install-Module $ModuleName -AllowClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue
                        $null = $ModulesSuccessfullyInstalled.Add($ModuleName)
                    }

                    $ModObj = [pscustomobject]@{
                        ModuleName          = $ModuleName
                        ManifestFileItem    = $(Get-Item $(Get-Module -ListAvailable $ModuleName).Path)
                    }

                    $null = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Add($ModObj)
                }
                catch {
                    Write-Warning $($_ | Out-String)
                    $null = $ModulesFailedInstall.Add($ModuleName)
                }

                try {
                    # Make sure the PSSession Type Accelerator exists
                    $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                    if ($TypeAccelerators.Name -notcontains "PSSession") {
                        [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
                    }

                    $ManifestFileItem = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        if (![bool]$(Get-Module -ListAvailable $args[0]) -and $args[1]) {
                            Install-Module $args[0] -AllowClobber -Force
                        }
                        $(Get-Item $(Get-Module -ListAvailable $args[0]).Path)
                    } -ArgumentList $ModuleName,$InstallModulesNotAvailableLocally -ErrorAction Stop -WarningAction SilentlyContinue

                    if ($ManifestFileItem) {
                        $null = $ModulesSuccessfullyInstalled.Add($ModuleName)

                        $ModObj = [pscustomobject]@{
                            ModuleName          = $ModuleName
                            ManifestFileItem    = $ManifestFileItem
                        }

                        $null = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Add($ModObj)
                    }
                }
                catch {
                    Write-Warning $($_ | Out-String)
                    $null = $ModulesFailedInstall.Add($ModuleName)
                }
            }
        }

        if ($ModulesNotFoundLocally.Count -ne $ModulesSuccessfullyInstalled.Count -and !$InstallModulesNotAvailableLocally) {
            $ErrMsg = "The following Modules were not found locally, and they will NOT be installed " +
            "because the -InstallModulesNotAvailableLocally switch was not used:`n$($ModulesNotFoundLocally -join "`n")"
            Write-Error $ErrMsg
            Write-Warning "No Modules have been Imported or Installed!"
            $global:FunctionResult = "1"
            return
        }
        if ($ModulesFailedInstall.Count -gt 0) {
            if ($ModulesSuccessfullyInstalled.Count -gt 0) {
                Write-Ouptut "The following Modules were successfully installed:`n$($ModulesSuccessfullyInstalled -join "`n")"
            }
            Write-Error "The following Modules failed to install:`n$($ModulesFailedInstall -join "`n")"
            Write-Warning "No Modules have been imported!"
            $global:FunctionResult = "1"
            return
        }
    }

    #$RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\RequiredLocallyAvailableModules.xml" -Force

    # Now all required modules are available locally, so let's filter to make sure we only try
    # to import the latest versions in case things are side-by-side install
    # Do for PSCoreModules...
    $PSCoreModDeps = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.clone()
    foreach ($ModObj in $PSCoreModDeps) {
        $MatchingModObjs = $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName
        }

        $AllVersions = $MatchingModObjs.ManifestFileItem.FullName | foreach {$(Import-PowerShellDataFile $_).ModuleVersion} | foreach {[version]$_}

        if ($AllVersions.Count -gt 1) {
            $VersionsSorted = $AllVersions | Sort-Object | Get-Unique
            $LatestVersion = $VersionsSorted[-1]

            $VersionsToRemove = $VersionsSorted[0..$($VersionsSorted.Count-2)]

            foreach ($Version in $($VersionsToRemove | foreach {$_.ToString()})) {
                [array]$ModObjsToRemove = $MatchingModObjs | Where-Object {
                    $(Import-PowerShellDataFile $_.ManifestFileItem.FullName).ModuleVersion -eq $Version -and $_.ModuleName -eq $ModObj.ModuleName
                }

                foreach ($obj in $ModObjsToRemove) {
                    $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies.Remove($obj)
                }
            }
        }
    }
    # Do for WinPSModules
    $WinModDeps = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.clone()
    foreach ($ModObj in $WinModDeps) {
        $MatchingModObjs = $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName
        }

        $AllVersions = $MatchingModObjs.ManifestFileItem.FullName | foreach {$(Import-PowerShellDataFile $_).ModuleVersion} | foreach {[version]$_}

        if ($AllVersions.Count -gt 1) {
            $VersionsSorted = $AllVersions | Sort-Object | Get-Unique
            $LatestVersion = $VersionsSorted[-1]

            $VersionsToRemove = $VersionsSorted[0..$($VersionsSorted.Count-2)]

            foreach ($Version in $($VersionsToRemove | foreach {$_.ToString()})) {
                [array]$ModObjsToRemove = $MatchingModObjs | Where-Object {
                    $(Import-PowerShellDataFile $_.ManifestFileItem.FullName).ModuleVersion -eq $Version -and $_.ModuleName -eq $ModObj.ModuleName
                }

                foreach ($obj in $ModObjsToRemove) {
                    $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies.Remove($obj)
                }
            }
        }
    }

    #endregion >> Prep

    $RequiredLocallyAvailableModulesScan

    #region >> Main

    #$RequiredLocallyAvailableModulesScan | Export-CliXml "$HOME\ReqModules.xml" -Force
    
    # Start Importing Modules...
    [System.Collections.ArrayList]$SuccessfulModuleImports = @()
    [System.Collections.ArrayList]$FailedModuleImports = @()
    foreach ($ModObj in $RequiredLocallyAvailableModulesScan.PSCoreModuleDependencies) {
        Write-Verbose "Attempting import of $($ModObj.ModuleName)..."
        try {
            Import-Module $ModObj.ModuleName -Scope Global -NoClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue

            $ModuleInfo = [pscustomobject]@{
                ModulePSCompatibility   = "PSCore"
                ModuleName              = $ModObj.ModuleName
                ManifestFileItem        = $ModObj.ManifestFileItem
            }
            if ([bool]$(Get-Module $ModObj.ModuleName) -and
            $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
            ) {
                $null = $SuccessfulModuleImports.Add($ModuleInfo)
            }
        }
        catch {
            Write-Verbose "Problem importing module '$($ModObj.ModuleName)'...trying via Manifest File..."

            try {
                Import-Module $ModObj.ManifestFileItem.FullName -Scope Global -NoClobber -Force -ErrorAction Stop -WarningAction SilentlyContinue

                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "PSCore"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                if ([bool]$(Get-Module $ModObj.ModuleName) -and
                $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
                ) {
                    $null = $SuccessfulModuleImports.Add($ModuleInfo)
                }
            }
            catch {
                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "PSCore"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                if ($FailedModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName) {
                    $null = $FailedModuleImports.Add($ModuleInfo)
                }
            }
        }
    }
    foreach ($ModObj in $RequiredLocallyAvailableModulesScan.WinPSModuleDependencies) {
        Write-Verbose "Attempting import of $($ModObj.ModuleName)..."
        try {
            Remove-Variable -Name "CompatErr" -ErrorAction SilentlyContinue
            $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
            Import-WinModule $ModObj.ModuleName -NoClobber -Force -ErrorVariable CompatErr 2>$tempfile

            if ($CompatErr.Count -gt 0) {
                Write-Verbose "Import of $($ModObj.ModuleName) failed..."
                Remove-Module $ModObj.ModuleName -ErrorAction SilentlyContinue
                Remove-Item $tempfile -Force -ErrorAction SilentlyContinue
                throw "ModuleNotImportedCleanly"
            }

            # Make sure the PSSession Type Accelerator exists
            $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
            if ($TypeAccelerators.Name -notcontains "PSSession") {
                [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
            }
            
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                Import-Module $args[0] -Scope Global -NoClobber -Force -WarningAction SilentlyContinue
            } -ArgumentList $ModObj.ModuleName -ErrorAction Stop

            $ModuleInfo = [pscustomobject]@{
                ModulePSCompatibility   = "WinPS"
                ModuleName              = $ModObj.ModuleName
                ManifestFileItem        = $ModObj.ManifestFileItem
            }

            $ModuleLoadedImplictly = [bool]$(Get-Module $ModObj.ModuleName)
            $ModuleLoadedInPSSession = [bool]$(
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    Get-Module $args[0]
                } -ArgumentList $ModObj.ModuleName -ErrorAction SilentlyContinue
            )

            if ($ModuleLoadedImplictly -or $ModuleLoadedInPSSession -and
            $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
            ) {
                $null = $SuccessfulModuleImports.Add($ModuleInfo)
            }
        }
        catch {
            Write-Verbose "Problem importing module '$($ModObj.ModuleName)'...trying via Manifest File..."

            try {
                if ($_.Exception.Message -eq "ModuleNotImportedCleanly") {
                    Write-Verbose "Import of $($ModObj.ModuleName) failed..."
                    throw "FailedImport"
                }

                Remove-Variable -Name "CompatErr" -ErrorAction SilentlyContinue
                $tempfile = [IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName())
                Import-WinModule $ModObj.ManifestFileItem.FullName -NoClobber -Force -ErrorVariable CompatErr 2>$tempfile

                if ($CompatErr.Count -gt 0) {
                    Remove-Module $ModObj.ModuleName -ErrorAction SilentlyContinue
                    Remove-Item $tempfile -Force -ErrorAction SilentlyContinue
                }

                # Make sure the PSSession Type Accelerator exists
                $TypeAccelerators = [psobject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::get
                if ($TypeAccelerators.Name -notcontains "PSSession") {
                    [PowerShell].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add("PSSession","System.Management.Automation.Runspaces.PSSession")
                }
                
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    Import-Module $args[0] -Scope Global -NoClobber -Force -WarningAction SilentlyContinue
                } -ArgumentList $ModObj.ManifestFileItem.FullName -ErrorAction Stop

                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "WinPS"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }

                $ModuleLoadedImplictly = [bool]$(Get-Module $ModObj.ModuleName)
                $ModuleLoadedInPSSession = [bool]$(
                    Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                        Get-Module $args[0]
                    } -ArgumentList $ModObj.ModuleName -ErrorAction SilentlyContinue
                )

                if ($ModuleLoadedImplictly -or $ModuleLoadedInPSSession -and
                $SuccessfulModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName
                ) {
                    $null = $SuccessfulModuleImports.Add($ModuleInfo)
                }
            }
            catch {
                $ModuleInfo = [pscustomobject]@{
                    ModulePSCompatibility   = "WinPS"
                    ModuleName              = $ModObj.ModuleName
                    ManifestFileItem        = $ModObj.ManifestFileItem
                }
                if ($FailedModuleImports.ManifestFileItem.FullName -notcontains $ModuleInfo.ManifestFileItem.FullName) {
                    $null = $FailedModuleImports.Add($ModuleInfo)
                }
            }
        }
    }

    #$SuccessfulModuleImports | Export-CliXml "$HOME\SuccessfulModImports.xml" -Force
    #$FailedModuleImports | Export-CliXml "$HOME\FailedModuleImports.xml" -Force

    # Now that Modules have been imported, we need to figure out which version of PowerShell we should use
    # for each Module. Modules might be able to be imported to PSCore, but NOT have all of their commands
    # available. So, let's filter out, remove, and uninstall all Modules with the least number of commands
    
    # Find all Modules that were successfully imported under both WinPS and PSCore
    $DualImportModules = $SuccessfulModuleImports | Group-Object -Property ModuleName | Where-Object {
        $_.Group.ModulePSCompatibility -contains "PSCore" -and $_.Group.ModulePSCompatibility -contains "WinPS"
    }
    # NOTE: The above $DualImportModules gives you something that looks like the following for each matching ModuleName
    <#
        Count Name                      Group
        ----- ----                      -----
            2 xActiveDirectory          {@{ModulePSCompatibility=PSCore; ModuleName=xActiveDirectory; ManifestFileItem=C:\Program Files\PowerShell\Modules\xActiveDi...
    #>
    # And each Group provides...
    <#
        ModulePSCompatibility ModuleName                   ManifestFileItem
        --------------------- ----------                   ----------------
        PSCore                xActiveDirectory             C:\Program Files\PowerShell\Modules\xActiveDirectory\2.19.0.0\xActiveDirectory.psd1
        WinPS                 xActiveDirectory             C:\Program Files\WindowsPowerShell\Modules\xActiveDirectory\2.19.0.0\xActiveDirectory.psd1
    #>
    
    foreach ($ModObjGroup in $DualImportModules) {
        $ModuleName = $ModObjGroup.Name

        # Check to see how many ExportedCommands are available in PSCore
        $PSCoreCmdCount = $($(Get-Module $ModuleName).ExportedCommands.Keys | Sort-Object | Get-Unique).Count

        # Check to see how many ExportedCommands are available in WinPS
        $WinPSCmdCount = Invoke-WinCommand -ComputerName localhost -ScriptBlock {
            $($(Get-Module $args[0]).ExportedCommands.Keys | Sort-Object | Get-Unique).Count
        } -ArgumentList $ModuleName

        if ($PSCoreCmdCount -ge $WinPSCmdCount) {
            Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                Remove-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Uninstall-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            } -ArgumentList $ModuleName

            $ObjectToRemove = $ModObjGroup.Group | Where-Object {$_.ModulePSCompatibility -eq "WinPS"}
            $null = $SuccessfulModuleImports.Remove($ObjectToRemove)
        }

        if ($PSCoreCmdCount -lt $WinPSCmdCount) {
            Remove-Module $ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            Uninstall-Module $ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

            $ObjectToRemove = $ModObjGroup.Group | Where-Object {$_.ModulePSCompatibility -eq "PSCore"}
            $null = $SuccessfulModuleImports.Remove($ObjectToRemove)
        }
    }

    if ($FailedModuleImports.Count -gt 0) {
        if ($PSVersionTable.PSEdition -ne "Core") {
            $AcceptableUnloadedModules = @("Microsoft.PowerShell.Core","WindowsCompatibility")
        }
        else {
            $AcceptableUnloadedModules = @()
        }

        [System.Collections.Arraylist]$UnacceptableUnloadedModules = @()
        foreach ($ModObj in $FailedModuleImports) {
            if ($AcceptableUnloadedModules -notcontains $ModObj.ModuleName -and
            $SuccessfulModuleImports.ModuleName -notcontains $ModObj.ModuleName
            ) {
                $null = $UnacceptableUnloadedModules.Add($ModObj)
            }
        }

        #$UnacceptableUnloadedModules | Export-CliXml "$HOME\UnacceptableUnloadedModules.xml" -Force

        if ($UnacceptableUnloadedModules.Count -gt 0) {
            $WrnMsgA = "The following Modules were not able to be loaded via implicit remoting:`n$($UnacceptableUnloadedModules.ModuleName -join "`n")"
            $WrnMsgB = "All code within '$InvocationMethod' that uses these Modules must be refactored similar to:`n" +
            "Invoke-WinCommand -ComputerName localhost -ScriptBlock {`n    <existing code>`n}"
            $WrnMsgC = "'$InvocationMethod' will probably *not* work in PowerShell Core!"
            Write-Warning $WrnMsgA
            Write-Warning $WrnMsgB
            Write-Warning $WrnMsgC
        }
    }

    # Uninstall the versions of Modules that don't work
    $AllLocallyAvailableModules = foreach ($ModPath in $AllWindowsPSModulePaths) {
        if (Test-Path $ModPath) {
            $ModuleBases = $(Get-ChildItem -Path $ModPath -Directory).FullName

            foreach ($ModuleBase in $ModuleBases) {
                [pscustomobject]@{
                    ModuleName          = $($ModuleBase | Split-Path -Leaf)
                    ManifestFileItem    = $(Get-ChildItem -Path $ModuleBase -Recurse -File -Filter "*.psd1")
                }
            }
        }
    }

    foreach ($ModObj in $SuccessfulModuleImports) {
        $ModulesToUninstall = $AllLocallyAvailableModules | Where-Object {
            $_.ModuleName -eq $ModObj.ModuleName -and
            $_.ManifestFileItem.FullName -ne $ModObj.ManifestFileItem.FullName
        }

        foreach ($ModObj2 in $ModulesToUninstall) {
            if ($ModObj2.ModuleManifestFileItem.FullName -match "\\PowerShell\\") {
                Remove-Module $ModObj2.ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                Uninstall-Module $ModObj2.ModuleName -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
            }
            if ($ModObj2.ModuleManifestFileItem.FullName -match "\\WindowsPowerShell\\") {
                Invoke-WinCommand -ComputerName localhost -ScriptBlock {
                    Remove-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                    Uninstall-Module $args[0] -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
                } -ArgumentList $ModObj2.ModuleName
            }
        }
    }

    [pscustomobject]@{
        SuccessfulModuleImports         = $SuccessfulModuleImports
        FailedModuleImports             = $FailedModuleImports
        UnacceptableUnloadedModules     = $UnacceptableUnloadedModules
    }
}

# SIG # Begin signature block
# MIIMiAYJKoZIhvcNAQcCoIIMeTCCDHUCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUxp3CW+2xwtyeeZo3EcfyiR8t
# q/+gggn9MIIEJjCCAw6gAwIBAgITawAAAB/Nnq77QGja+wAAAAAAHzANBgkqhkiG
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
# NwIBCzEOMAwGCisGAQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFBmVOCq5pvvyrQbs
# STAssMQZKukyMA0GCSqGSIb3DQEBAQUABIIBAGgLCHj3I+BZNBMUAonY1ztINrvk
# ZYFLnbBb+NNdzRMbdt8cyFjcri7Op9dY8WQETe+ulepDR5loyDA7pX0RCWEkcwUg
# IbTOF2qdMs3Lwv3x6X5SbH93f1fxyl/eLqzx0aMFj/8pTJs59DHmdCu6AwH1pOQy
# itbIGEVNDBUHnABHx8gQSYKqorO3sj8QKPq3c/6wBMH3eRROD5rZ3G3ybJFF8InC
# UCmoyOATvBERECeY8DiaNZlwsOR0ZdP+VgacxigMWxs4+9BkivR58lKV5fKG6QYk
# R7E81uKlk5I1wNE3/7+WWIMuJgeC9noj4h+CCBSdSCpUVQT20Z1Uz+yynlc=
# SIG # End signature block
