<#
    .SYNOPSIS
        Retrieves the inventory data for a cluster.
    
    .DESCRIPTION
        Retrieves the inventory data for a cluster.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ClusterInventory {
    import-module CimCmdlets
    
    # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
    import-module FailoverClusters -ErrorAction SilentlyContinue
    
    <#
        .SYNOPSIS
        Get the name of this computer.
        
        .DESCRIPTION
        Get the best available name for this computer.  The FQDN is preferred, but when not avaialble
        the NetBIOS name will be used instead.
    #>
    function getComputerName() {
        $computerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object Name, DNSHostName
    
        if ($computerSystem) {
            $computerName = $computerSystem.DNSHostName
    
            if ($computerName -eq $null) {
                $computerName = $computerSystem.Name
            }
    
            return $computerName
        }
    
        return $null
    }
    
    <#
        .SYNOPSIS
        Are the cluster PowerShell cmdlets installed on this server?
        
        .DESCRIPTION
        Are the cluster PowerShell cmdlets installed on this server?
    #>
    function getIsClusterCmdletAvailable() {
        $cmdlet = Get-Command "Get-Cluster" -ErrorAction SilentlyContinue
    
        return !!$cmdlet
    }
    
    <#
        .SYNOPSIS
        Get the MSCluster Cluster CIM instance from this server.
        
        .DESCRIPTION
        Get the MSCluster Cluster CIM instance from this server.
    #>
    function getClusterCimInstance() {
        $namespace = Get-CimInstance -Namespace root/MSCluster -ClassName __NAMESPACE -ErrorAction SilentlyContinue
        if ($namespace) {
            return Get-CimInstance -Namespace root/mscluster MSCluster_Cluster -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object fqdn, S2DEnabled
        }
    
        return $null
    }
    
    <#
        .SYNOPSIS
        Get some basic information about the cluster from the cluster.
        
        .DESCRIPTION
        Get the needed cluster properties from the cluster.
    #>
    function getClusterInfo() {
        $returnValues = @{}
    
        $returnValues.Fqdn = $null
        $returnValues.isS2DEnabled = $false
    
        $cluster = getClusterCimInstance
        if ($cluster) {
            $returnValues.Fqdn = $cluster.fqdn
            $returnValues.isS2DEnabled = ($cluster.S2DEnabled -eq 1)
        }
    
        return $returnValues
    }
    
    <#
        .SYNOPSIS
        Are the cluster PowerShell Health cmdlets installed on this server?
        
        .DESCRIPTION
        Are the cluster PowerShell Health cmdlets installed on this server?
    #>
    function getisClusterHealthCmdletAvailable() {
        $cmdlet = Get-Command -Name "Get-HealthFault" -ErrorAction SilentlyContinue
    
        return !!$cmdlet
    }
    <#
        .SYNOPSIS
        Are the Britannica (sddc management resources) available on the cluster?
        
        .DESCRIPTION
        Are the Britannica (sddc management resources) available on the cluster?
    #>
    function getIsBritannicaEnabled() {
        return (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_Cluster -ErrorAction SilentlyContinue) `
            -ne $null
    }
    
    <#
        .SYNOPSIS
        Are the Britannica (sddc management resources) virtual machine available on the cluster?
        
        .DESCRIPTION
        Are the Britannica (sddc management resources) virtual machine available on the cluster?
    #>
    function getIsBritannicaVirtualMachineEnabled() {
        return (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualMachine -ErrorAction SilentlyContinue) `
            -ne $null
    }
    
    <#
        .SYNOPSIS
        Are the Britannica (sddc management resources) virtual switch available on the cluster?
        
        .DESCRIPTION
        Are the Britannica (sddc management resources) virtual switch available on the cluster?
    #>
    function getIsBritannicaVirtualSwitchEnabled() {
        return (Get-CimInstance -Namespace root/sddc/management -ClassName SDDC_VirtualSwitch -ErrorAction SilentlyContinue) `
            -ne $null
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    $clusterInfo = getClusterInfo
    
    $result = New-Object PSObject
    
    $result | Add-Member -MemberType NoteProperty -Name 'Fqdn' -Value $clusterInfo.Fqdn
    $result | Add-Member -MemberType NoteProperty -Name 'IsS2DEnabled' -Value $clusterInfo.isS2DEnabled
    $result | Add-Member -MemberType NoteProperty -Name 'IsClusterHealthCmdletAvailable' -Value (getIsClusterHealthCmdletAvailable)
    $result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaEnabled' -Value (getIsBritannicaEnabled)
    $result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualMachineEnabled' -Value (getIsBritannicaVirtualMachineEnabled)
    $result | Add-Member -MemberType NoteProperty -Name 'IsBritannicaVirtualSwitchEnabled' -Value (getIsBritannicaVirtualSwitchEnabled)
    $result | Add-Member -MemberType NoteProperty -Name 'IsClusterCmdletAvailable' -Value (getIsClusterCmdletAvailable)
    $result | Add-Member -MemberType NoteProperty -Name 'CurrentClusterNode' -Value (getComputerName)
    
    $result
    
}
    