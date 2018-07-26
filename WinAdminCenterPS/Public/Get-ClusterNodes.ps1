<#
    .SYNOPSIS
        Retrieves the inventory data for cluster nodes in a particular cluster.
    
    .DESCRIPTION
        Retrieves the inventory data for cluster nodes in a particular cluster.

    .NOTES
        This function is pulled directly from the real Microsoft Windows Admin Center

        PowerShell scripts use rights (according to Microsoft):
        We grant you a non-exclusive, royalty-free right to use, modify, reproduce, and distribute the scripts provided herein.

        ANY SCRIPTS PROVIDED BY MICROSOFT ARE PROVIDED “AS IS” WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
        INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS OR A PARTICULAR PURPOSE.
    
    .ROLE
        Readers
#>
function Get-ClusterNodes {
    import-module CimCmdlets
    
    # JEA code requires to pre-import the module (this is slow on failover cluster environment.)
    import-module FailoverClusters -ErrorAction SilentlyContinue
    
    <#
        .SYNOPSIS
        Are the cluster PowerShell cmdlets installed?
        
        .DESCRIPTION
        Use the Get-Command cmdlet to quickly test if the cluster PowerShell cmdlets
        are installed on this server.
    #>
    function getClusterPowerShellSupport() {
        $cmdletInfo = Get-Command 'Get-ClusterNode' -ErrorAction SilentlyContinue
    
        return $cmdletInfo -and $cmdletInfo.Name -eq "Get-ClusterNode"
    }
    
    <#
        .SYNOPSIS
        Get the cluster nodes using the cluster CIM provider.
        
        .DESCRIPTION
        When the cluster PowerShell cmdlets are not available fallback to using
        the cluster CIM provider to get the needed information.
    #>
    function getClusterNodeCimInstances() {
        # Change the WMI property NodeDrainStatus to DrainStatus to match the PS cmdlet output.
        return Get-CimInstance -Namespace root/mscluster MSCluster_Node -ErrorAction SilentlyContinue | `
            Microsoft.PowerShell.Utility\Select-Object @{Name="DrainStatus"; Expression={$_.NodeDrainStatus}}, DynamicWeight, Name, NodeWeight, FaultDomain, State
    }
    
    <#
        .SYNOPSIS
        Get the cluster nodes using the cluster PowerShell cmdlets.
        
        .DESCRIPTION
        When the cluster PowerShell cmdlets are available use this preferred function.
    #>
    function getClusterNodePsInstances() {
        return Get-ClusterNode -ErrorAction SilentlyContinue | Microsoft.PowerShell.Utility\Select-Object DrainStatus, DynamicWeight, Name, NodeWeight, FaultDomain, State
    }
    
    <#
        .SYNOPSIS
        Use DNS services to get the FQDN of the cluster NetBIOS name.
        
        .DESCRIPTION
        Use DNS services to get the FQDN of the cluster NetBIOS name.
        
        .Notes
        It is encouraged that the caller add their approprate -ErrorAction when
        calling this function.
    #>
    function getClusterNodeFqdn($clusterNodeName) {
        return  ([System.Net.Dns]::GetHostEntry($clusterNodeName)).HostName
    }
    
    <#
        .SYNOPSIS
        Get the cluster nodes.
        
        .DESCRIPTION
        When the cluster PowerShell cmdlets are available get the information about the cluster nodes
        using PowerShell.  When the cmdlets are not available use the Cluster CIM provider.
    #>
    function getClusterNodes() {
        $isClusterCmdletAvailable = getClusterPowerShellSupport
    
        if ($isClusterCmdletAvailable) {
            $clusterNodes = getClusterNodePsInstances
        } else {
            $clusterNodes = getClusterNodeCimInstances
        }
    
        $clusterNodeMap = @{}
    
        foreach ($clusterNode in $clusterNodes) {
            $clusterNodeName = $clusterNode.Name.ToLower()
            $clusterNodeFqdn = getClusterNodeFqdn $clusterNodeName -ErrorAction SilentlyContinue
    
            $clusterNodeResult = New-Object PSObject
    
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FullyQualifiedDomainName' -Value $clusterNodeFqdn
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'Name' -Value $clusterNodeName
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DynamicWeight' -Value $clusterNode.DynamicWeight
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'NodeWeight' -Value $clusterNode.NodeWeight
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'FaultDomain' -Value $clusterNode.FaultDomain
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'State' -Value $clusterNode.State
            $clusterNodeResult | Add-Member -MemberType NoteProperty -Name 'DrainStatus' -Value $clusterNode.DrainStatus
    
            $clusterNodeMap.Add($clusterNodeName, $clusterNodeResult)
        }
    
        return $clusterNodeMap
    }
    
    ###########################################################################
    # main()
    ###########################################################################
    
    getClusterNodes
    
}
    