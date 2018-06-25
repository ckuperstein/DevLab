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
function Get-VMHealthStatus {
    [CmdletBinding(DefaultParameterSetName='Host-DNS')]
    param (
        # Host
        [Parameter(Mandatory=$true,Position=0,ParameterSetName='Host-DNS')]
        [string[]]
        $Server,
        # Credentials
        [Parameter(Mandatory=$true,Position=1,ParameterSetName='Host-DNS')]
        [pscredential]
        $Credential,
        # Check DNS
        [Parameter(Mandatory=$false,Position=2,ParameterSetName='Host-DNS')]
        [switch]
        $CheckDNS,
        # Check AD
        [Parameter(Mandatory=$false,Position=3,ParameterSetName='Host-DNS')]
        [switch]
        $CheckAD,
        # Export to this file path
        [Parameter(Mandatory=$true,Position=4,ParameterSetName='Host-DNS')]
        [string]
        $ExportPath
    )
    
    begin {
        $ErrorActionPreference = 'Stop'
        try{
            Import-Module ActiveDirectory
            Import-Module VMware.PowerCLI
        }
        catch {
            Write-Error -Message "Could not import one or more modules"
        }
    }
    
    process {
        foreach ($Hostname in $Server){
            try{
                Connect-VIServer $Hostname -Credential $Credential
            }
            catch{
                Write-Error -Message "Could not connect to $Hostname" -ErrorAction 'Continue'
            }
        }

        try{
            $VMs = Get-VM
            $Today = Get-Date
            $ConfNameContext = Get-ADRootDSE | Select-Object -Expandproperty configurationNamingContext
            [int]$TombStoneThreshold = (Get-ADObject -Identity “CN=Directory Service,CN=Windows NT,CN=Services,$ConfNameContext” -properties tombstonelifetime).tombstonelifetime
        }
        catch {
            Write-Warning -Message "Could not retrieve VMs from one or more connected servers."
        }
        
        $VMResults = [System.Collections.ArrayList]::New()
        $t = ($VMs | Measure-Object).Count
        foreach ($VM in $VMs){
            $fqdn = $VM.Guest.Hostname
            $i = [array]::IndexOf($VMs,$VM)
            Write-Progress -Activity 'Analyzing VM Health State' -Status ('Running ' + [math]::Round(($i/$t*100),2) + '% | ' + "$i/$t Machines Checked") -PercentComplete ($i/$t*100)

            if ($CheckDNS){
                try{
                    if ($fqdn -ne $null){
                        $IPFromDNS = [System.Net.Dns]::GetHostAddresses($fqdn).IPAddressToString
                    }
                }
                catch{
                    Write-Warning -Message ("Could not resolve IP Address for host $fqdn")
                    $IPFromDNS = $null
                }

                try{
                    if ($fqdn -ne $null){
                        $HostnameFromDNS = [System.Net.Dns]::GetHostEntry($VM.Guest.IPAddress[0]).Hostname
                    }
                }
                catch{
                    Write-Warning -Message ("Could not resolve a hostname in DNS from $fqdn")
                    $HostnameFromDNS = $null
                }
            }

            if ($CheckAD){
                try{
                    if ($fqdn -ne $null){
                        $ServerString = [System.Collections.ArrayList]::New($fqdn.Split('.'))
                        $ComputerName = $ServerString[0]
                        $ServerString.Remove($ServerString[0])
                        $SearchBase = [System.Collections.ArrayList]::New()
                        foreach ($i in $ServerString){
                            $SearchBase.Add('DC='+$i) | Out-Null
                        }
                        $SearchBase = $SearchBase -Join ','
                        $ServerString = $ServerString -Join '.'

                        Write-Information "Getting AD Object for $fqdn"
                        $ADObj = Get-ADComputer -Filter ('Name -like "{0}"' -f $ComputerName) -SearchBase $SearchBase -Server $ServerString -Properties lastLogonTimeStamp,pwdLastSet
                        $plsd = [DateTime]::FromFileTime($ADObj.pwdLastSet)
                        $lld = [DateTime]::FromFileTime($ADObj.lastLogonTimeStamp)
                        $pwdLastSetDiff = ($Today - $plsd)
                        $lastLogonDiff = ($Today - $lld)
                    }
                    else {
                        $pwdLastSetDiff = $null
                        $lastLogonDiff = $null
                    }
                }
                catch{
                    Write-Warning -Message ("Could not retrieve AD Object for $fqdn")
                }
            }
            
            # Time to start checking tombstone status
            $VMResultObj = [PSCustomObject]@{
                GuestName = $VM.Guest.Hostname
                GuestDNSName = (@{$true='';$false=$HostnameFromDNS}[$HostnameFromDNS -eq $null])
                GuestId = $VM.Guest.RuntimeGuestId
                VmName = $VM.Name
                VmId = $VM.Id
                PasswordLastSetDays = $pwdLastSetDiff.Days
                LastLogonDays = $lastLogonDiff.Days
                Tombstoned = (@{$true='Yes';$false='No'}[(($pwdLastSetDiff.Days -gt $TombStoneThreshold) -and ($lastLogonDiff.Days -gt $TombStoneThreshold))])
                ADStatus = (@{$true='Present';$false='Absent'}[$ADObj -ne $null])
                GuestIPAddress = $VM.Guest.IPAddress[0]
                GuestDNSIPAddress = ($IPFromDNS -Join ',')
            }

            $VMResults.Add($VMResultObj) | Out-Null
        }
        
    }
    
    end {
        $VMResults | Export-CSV $ExportPath -NoTypeInformation
        return $VMResults
    }
}