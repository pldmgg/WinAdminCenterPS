@{
    # Some defaults for all dependencies
    PSDependOptions = @{
        Target = '$ENV:USERPROFILE\Documents\WindowsPowerShell\Modules'
        AddToPath = $True
    }

    # Grab some modules without depending on PowerShellGet
    'psake' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'PSDeploy' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'BuildHelpers' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'Pester' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'PSScriptAnalyzer' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
    'Assert' = @{
        DependencyType  = 'PSGalleryNuget'
        Version         = 'Latest'
    }
}
