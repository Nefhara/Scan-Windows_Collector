####################
##### CSS CODE #####
####################

$header = @"
<style>
    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #e68a00;
        font-size: 28px;

    }
    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;

    }

   table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #395870;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
</style>
"@



###########################
##### POWERSHELL CODE #####
###########################

###################################
### FONCTION CALCUL SOUS RESEAU ###
###################################
function Get-IpRange {
    [CmdletBinding(ConfirmImpact = 'None')]

    Param(
        [Parameter(Mandatory, HelpMessage = 'Please enter a subnet in the form a.b.c.d/#', ValueFromPipeline, Position = 0)]
        [string[]] $Subnets
    )

    begin 
    {
        Write-Verbose -Message "Starting [$($MyInvocation.Mycommand)]"
    }

    process 
    {
        foreach ($subnet in $subnets) 
        {
            if ($subnet -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$') 
            {
                #Split IP and subnet
                $IP = ($Subnet -split '\/')[0]
                [int] $SubnetBits = ($Subnet -split '\/')[1]
                if ($SubnetBits -lt 7 -or $SubnetBits -gt 30) 
                {
                    Write-Error -Message 'The number following the / must be between 7 and 30'
                    break
                }

                #Convert IP into binary
                #Split IP into different octects and for each one, figure out the binary with leading zeros and add to the total
                $Octets = $IP -split '\.'
                $IPInBinary = @()

                foreach ($Octet in $Octets) 
                {
                    #convert to binary
                    $OctetInBinary = [convert]::ToString($Octet, 2)
                    #get length of binary string add leading zeros to make octet
                    $OctetInBinary = ('0' * (8 - ($OctetInBinary).Length) + $OctetInBinary)
                    $IPInBinary = $IPInBinary + $OctetInBinary
                }

                $IPInBinary = $IPInBinary -join ''
                #Get network ID by subtracting subnet mask
                $HostBits = 32 - $SubnetBits
                $NetworkIDInBinary = $IPInBinary.Substring(0, $SubnetBits)
                #Get host ID and get the first host ID by converting all 1s into 0s
                $HostIDInBinary = $IPInBinary.Substring($SubnetBits, $HostBits)
                $HostIDInBinary = $HostIDInBinary -replace '1', '0'
                #Work out all the host IDs in that subnet by cycling through $i from 1 up to max $HostIDInBinary (i.e. 1s stringed up to $HostBits)
                #Work out max $HostIDInBinary
                $imax = [convert]::ToInt32(('1' * $HostBits), 2) - 1
                $IPs = @()

                #Next ID is first network ID converted to decimal plus $i then converted to binary
                For ($i = 1 ; $i -le $imax ; $i++) 
                {
                    #Convert to decimal and add $i
                    $NextHostIDInDecimal = ([convert]::ToInt32($HostIDInBinary, 2) + $i)
                    #Convert back to binary
                    $NextHostIDInBinary = [convert]::ToString($NextHostIDInDecimal, 2)
                    #Add leading zeros
                    #Number of zeros to add
                    $NoOfZerosToAdd = $HostIDInBinary.Length - $NextHostIDInBinary.Length
                    $NextHostIDInBinary = ('0' * $NoOfZerosToAdd) + $NextHostIDInBinary
                    #Work out next IP
                    #Add networkID to hostID
                    $NextIPInBinary = $NetworkIDInBinary + $NextHostIDInBinary
                    #Split into octets and separate by . then join
                    $IP = @()

                    For ($x = 1 ; $x -le 4 ; $x++) 
                    {
                        #Work out start character position
                        $StartCharNumber = ($x - 1) * 8
                        #Get octet in binary
                        $IPOctetInBinary = $NextIPInBinary.Substring($StartCharNumber, 8)
                        #Convert octet into decimal
                        $IPOctetInDecimal = [convert]::ToInt32($IPOctetInBinary, 2)
                        #Add octet to IP
                        $IP += $IPOctetInDecimal
                    }
                   
                    $IP = $IP -join '.'
                    $IPs += "$IP"                   
                }

                #Write-Output -InputObject $IPs
                return $IPs
            } 
            
            else 
            {
                Write-Error -Message "Subnet [$subnet] is not in a valid format"
            }
        }
    }

    end 
    {
        Write-Verbose -Message "Ending [$($MyInvocation.Mycommand)]"
    }
}


#############################
### NETWORK SCAN FUNCTION ###
#############################
function NetworkScan {
    param(
        [int]$thread
    )

    # Get list of network interfaces (exclude virtual interfaces)
    $networkInterfaces = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Virtual -eq $false }

    # For each interface, determines the IP address and mask
    foreach ($interface in $networkInterfaces) {
        Write-Host " Network scan through interface : $($interface.Name) "

        # Get the IP address and subnet mask of the interface
        $ipAddressObject = $interface | Get-NetIPAddress -AddressFamily IPv4

        $ipAddress = $ipAddressObject.IPAddress
        $subnetMask = $ipAddressObject.PrefixLength

        $network = "$ipAddress/$subnetMask"
    }

    # Calculation of all IPs in the subnet via call to the "Get-IpRange" function
    $allip = (Get-IpRange -Subnets $network)
    $nb_ip = $allip.Count


    ###############################
    ### !!! START THREADING !!! ###
    ###############################

    # Ping all IP addresses in the network defined above

    # Maximum number of simultaneous jobs, RAM consumption: ~500MB, speed: x10
    $maxConcurrentJobs = $thread

    # Create a table to store jobs
    $jobs = @()

    # Variable progress bar
    $i = 0

    # Runs jobs asynchronously for each IP address
    foreach ($ip in $allip) {

       # Shows the processed IP

       # Percentage calculation
       $i += 1
       $pourcentage = ($i / $nb_ip) * 100
       $pourcentage_barre = [math]::Floor($pourcentage)

       # Showing the progress bar
       Write-Progress -Activity "Network scan in progress ... ($pourcentage_barre %)" -PercentComplete $pourcentage 

       $scriptblock = {
           param($ip)
           # Ping test command with errors ignored
           Test-Connection -ComputerName $ip -Count 1 -ErrorAction SilentlyContinue
       }
       
       # Launch of each job
       $job = Start-Job -ScriptBlock $scriptblock -ArgumentList $ip
       $jobs += $job

       # Wait if the number of jobs reaches the limit
       while ((Get-Job -State Running).Count -ge $maxConcurrentJobs) {
           Start-Sleep -Milliseconds 500
       }
    }

    # Wait for all jobs to finish
    Wait-Job -Job $jobs | Out-Null

    # Retrieve job results
    $jobresults = Receive-Job -Job $jobs

    # Delete all jobs
    Remove-Job -Job $jobs

    # End of progress bar
    Write-Progress -Activity "Network scan in progress ... ($pourcentage_barre %)" -Completed

    #############################
    ### !!! END THREADING !!! ###
    #############################

    # Resolution via the ARP table of all responded @IPs
    foreach ($result in $jobresults) 
    {
        if ($result.StatusCode -eq 0) 
        {
            $ip = $result.Address

            # MAC Address Resolution
            try {
                $mac = (Get-NetNeighbor -IPAddress $ip -ErrorAction Stop).LinkLayerAddress
                }

            catch {
                $mac = "UNKNOW"
                }

            # Hostname resolution via DNS
            try {
                # DNS resolution for each IP
                $computername = (Resolve-DnsName $ip -ErrorAction Stop).NameHost
                }

            catch {
                try{
                    $computername = [System.Net.Dns]::GetHostEntry("$ip").HostName
                }
                catch{
                    $computername = "UNKNOW"
                    }
                }

            $script:tabnetworkinfo += [PSCustomObject]@{
                "Adresse IP" = $ip
                "Adresse MAC" = $mac
                "Nom d'hôte" = $computername
            }           
        }
    } 
}


###################################
### SYSTEM INFORMATION FUNCTION ###
###################################
function SystemInformation{
    <#  0 (Unknow) : unknow drive
        1 (No Root Directory) : no drive root directory
        2 (Removable Disk) : USB Drive
        3 (Local Disk) : Local Drive
        4 (Network Drive) : Network Drive
        5 (Compact Disk) : CD-ROM Drive
        6 (RAM Disk) : RAM Drive
    #>

    $drive_type = @(2, 3, 5)
    
    try
    {
        # Drive information collection
        $tmp_disque_info = gwmi Win32_logicaldisk -ComputerName $computer | Where-Object {$_.DriveType -in $drive_type}
        $script:strdisqueinfo =  $tmp_disque_info | Select-Object @{n="Computer";e={$computer}}, @{n="Volume";e={$_.VolumeName}}, @{n="Letter";e={$_.DeviceID}}, @{n="Disk size (GB)";e={[math]::Round($_.Size/1GB,2)}}, @{n="Free space (GB)";e={[math]::Round($_.FreeSpace/1GB,2)}},@{n="Usage percentage";e={$([math]::Ceiling((1-$($([double]::Parse($_.FreeSpace))/$([double]::Parse($_.Size))))*100)).ToString()+"%"}}

        # RAM information collection
        $script:raminfo = Get-CimInstance -ClassName CIM_PhysicalMemory | Select-Object @{n="RAM type";e={$_.Description}}, @{n="Manufacturer";e={$_.manufacturer}}, @{n="Capacity (GB)";e={[math]::Round($_.Capacity/1GB,2)}}

        # System information collection
        $script:sysinfo = Get-ComputerInfo WindowsEditionId, WindowsProductName, WindowsRegisteredOwner, BiosFirmwareType, CsDNSHostName, CsDomain, CsProcessors, CsUserName | Select-Object @{n="Windows Edition ID";e={$_.WindowsEditionId}}, @{n="Windows Product Name";e={$_.WindowsProductName}}, @{n="Owner";e={$_.WindowsRegisteredOwner}}, @{n="BIOS";e={$_.BiosFirmwareType}}, @{n="Hostname";e={$_.CsDNSHostName}}, @{n="Domain";e={$_.CsDomain}}, @{n="Processor";e={$_.CsProcessors.Name}}, @{n="Username";e={$_.CsUserName}}
    }

    catch
    {
        Write-Host "Error retrieving system information" -ForegroundColor Red
    }
}


##############################
### SOFTWARE INFO FUNCTION ###
##############################
function ApplicationInformation {
    $retour_softs = @()
    $regs = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\','HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall'
    
    ForEach($reg in $regs)
    {
        If($reg -Match 'Wow6432Node')
        {
            $plateforme = 32
        }
        
        else
        {
            $plateforme = 64
        }
    
        $items = Get-ChildItem -Path $reg
    
        ForEach($item in $items)
        {
            $key = $item.Name -Replace 'HKEY_LOCAL_MACHINE','HKLM:'
            
            try
            {
                $logiciel = Get-ItemPropertyValue -Path $key -Name 'DisplayName' -ErrorAction SilentlyContinue
            }
            catch
            {
                $logiciel = ''
            }
    
            try
            {
                $install = Get-ItemPropertyValue -Path $key -Name 'InstallDate'  -ErrorAction SilentlyContinue
            }
            catch
            {
                $install = ''
            }
    
            try
            {
                $version = Get-ItemPropertyValue -Path $key -Name 'DisplayVersion'   -ErrorAction SilentlyContinue
            }
            catch
            {
                $version = ''
            }
    
            If($version)
            {
                $retour_softs += [PSCustomObject]@{logiciel=$logiciel; version=$version; install=$install; plateforme=$plateforme}
            }
        }
    }
    
    $tmp = $retour_softs | Sort -Unique -Property logiciel, version, install
    $script:softs = $tmp | Select-Object @{n="Software";e={$_.logiciel}}, @{n="Version";e={$_.version}}, @{n="Installation date";e={([DateTime]::ParseExact($_.install, "yyyyMMdd", $null)).ToString("dd/MM/yyyy")}}, @{n="Plateform (x64 ou x32)";e={$_.plateforme}}
}


#####################
### MENU FUNCTION ###
#####################
function menu{
    Clear-Host
    Write-Host " Menu : "
    Write-Host "    1. Full scan (network + system)"
    Write-Host "    2. Computer scan (system)"
    Write-Host "    3. To leave"
}

###################################
########## MAIN FUNCTION ##########
###################################
function main{
    # Variable
    $computer = (Get-ComputerInfo).CSName
    $output_pdf = ".\Collector-$computer.html"

    # Optimisation thread
    #$free_ram = ([math]::Floor(((Get-WmiObject -Class Win32_OperatingSystem).FreePhysicalMemory)/1KB)) - 1000
    #$thread = [math]::Floor($free_ram / 600)
    $thread = 10

    $script:tabnetworkinfo = @()
    $script:strdisqueinfo = ""
    $script:raminfo = ""
    $script:sysinfo = ""
    $script:softs = ""

    while ($true){
        # Print menu
        menu

        # User choice
        $choice = Read-Host " Choice (1, 2 or 3) : "

        # Choice
        switch ($choice){
            '1' {
                Clear-Host
                Write-Host " Running a full scan "

                # Network scan
                NetworkScan -thread $thread
                Write-Host " [FINISHED] Network scan "

                # System information collection
                Write-Host " [IN PROGRESS] System scan "
                SystemInformation
                Write-Host " [FINISHED] System scan "

                # Software information collection
                Write-Host " [IN PROGRESS] Software scan "
                ApplicationInformation
                Write-Host " [FINISHED] Software scan "

                # HTML Report settings
                $network_info = $script:tabnetworkinfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> Network information </h2>"
                $disque_info = $script:strdisqueinfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> Disk information </h2>"
                $ram_info = $script:raminfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> RAM information </h2>"
                $sys_info = $script:sysinfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> System information </h2>"
                $softs_info = $script:softs | ConvertTo-Html -As Table -Fragment -PreContent "<h2> Software information </h2>"

                $title = "<h1> $computer - Creation data : $(Get-Date)</h1>"
                $body = "$title $disque_info $ram_info $sys_info $softs_info $network_info"
            }

            '2' {
                Clear-Host
                Write-Host " Running a computer scan "

                # System information collection
                Write-Host " [IN PROGRESS] System scan "
                SystemInformation
                Write-Host " [FINISHED] System scan "

                # Software information collection
                Write-Host " [IN PROGRESS] Software scan "
                ApplicationInformation
                Write-Host " [FINISHED] Software scan "

                # HTML Report settings
                $disque_info = $script:strdisqueinfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> Disk information </h2>"
                $ram_info = $script:raminfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> RAM information </h2>"
                $sys_info = $script:sysinfo | ConvertTo-Html -As Table -Fragment -PreContent "<h2> System information </h2>"
                $softs_info = $script:softs | ConvertTo-Html -As Table -Fragment -PreContent "<h2> Software information </h2>"

                $title = "<h1> $computer - Creation date : $(Get-Date)</h1>"
                $body = "$title $disque_info $ram_info $sys_info $softs_info"
            }

            '3' {
                Write-Host " End of program "
                return
            }
        }

    # HTML Report generation
    $report = ConvertTo-Html -Body $body -Head $header -Title "Data collection $computer"
    $report | Out-File $output_pdf

    # Reading HTML report
    start $output_pdf
    
    }
}


##################  MAIN  ###################
main