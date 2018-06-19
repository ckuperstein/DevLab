<#
.SYNOPSIS
Auditing VMWare vSphere servers for VM lifecycle status.

.DESCRIPTION
Reaches out to each vSphere server/host and pulls the VMs off to check against:
-DNS Forward Lookup Zones
-DNS Reverse PTR records
-AD Tombstone status
-AD LastPasswordSetDate
-TCP/IP Status (Ping, WMI if available)
#>
function Compare-VMState {
    [CmdletBinding(DefaultParameterSetName='Host-DNS')]
    param (
        # Host
        [Parameter(Mandatory=$true,Position=0,ParameterSetName='Host-DNS')]
        [string[]]
        $Server,
        # Check DNS
        [Parameter(Mandatory=$false,Position=1,ParameterSetName='Host-DNS')]
        [switch]
        $CheckDNS,
        # DNS Zone Name
        [Parameter(Mandatory=$true)] # I'll deal with param sets later
        [string[]]
        $Zone,
        # Check AD
        [Parameter(Mandatory=$false)]
        [switch]
        $CheckAD
    )
    
    begin {
        $ErrorActionPreference = 'Stop'
        try{
            $Modules = @('ActiveDirectory','VMWare.PowerCLI')
            foreach ($M in $Modules){
                Import-Module $M
            }
        }
        catch {
            Write-Error -Message "Could not import one or more modules"
        }
    }
    
    process {

        foreach ($Hostname in $Server){
            try{
                Connect-VIServer $Hostname
            }
            catch{
                Write-Error -Message "Could not connect to $Hostname"
            }
        }

        try{
            $VMs = Get-VM
        }
        catch {
            Write-Warning -Message "Could not retrieve VMs from one or more connected servers."
        }

        foreach ($VM in $VMs){
            $fqdn = ($VM + '.' + $Zone)

            if ($CheckDNS){
                try{
                    $IPFromDNS = [System.Net.Dns]::GetHostAddresses($fqdn)
                }
                catch{
                    Write-Warning -Message "Could not resolve IP Address for host {0}" -f $fqdn
                    $IPFromDNS = $null
                }
            }

            if ($CheckAD){
                try{
                    $LastLogonTimeStamp = [DateTime]::FromFileTime((Get-ADComputer -Identity $fqdn -Properties LastLogonTimeStamp).LastLogonTimeStamp)
                }
                catch{
                    Write-Warning -Message "Could not retrieve time stamp from AD"
                }
            }


        }
        
    }
    
    end {
    }
}