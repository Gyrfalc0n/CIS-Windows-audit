function Write-Double($text) {
    Write-Host $text
    ResultToString($text)
}
function ShowGeneralInformation {
    # Hardware Model
    $hardwareModel = Get-WmiObject Win32_ComputerSystem | Select-Object Model
    # BIOS or UEFI Version
    $biosVersion = Get-WmiObject Win32_BIOS | Select-Object Version
    # Installed RAM slots, size of RAM on each slot
    $ramSlots = Get-WmiObject Win32_PhysicalMemory | Select-Object DeviceLocator, Capacity
    # Processor Information
    $processorInfo = Get-WmiObject Win32_Processor | Select-Object Name, MaxClockSpeed, NumberOfCores
    # Network Adapter Characteristics, MAC/IP Addresses
    $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object Description, MACAddress, IPAddress
    # Types and number of installed hard drives, BitLocker information
    $hardDrives = Get-WmiObject Win32_DiskDrive | Select-Object MediaType, Size
    $bitlockerInfo = Get-BitLockerVolume | Select-Object VolumeType, ProtectionStatus
    # Display known WiFi networks and their passwords
    $wifiNetworks = netsh wlan show profiles | Select-String "All User Profiles" | ForEach-Object { $_.ToString().Split(":")[1].Trim() }
    $wifiPasswords = $wifiNetworks | ForEach-Object { (netsh wlan show profile name=$_ key=clear) -match "Key Content            : (.*)" | Out-Null; $matches[1] }
    $wifiInformation = @()
    for ($i = 0; $i -lt $wifiNetworks.Length; $i++) {
        $wifiInformation += [PSCustomObject]@{
            Network = $wifiNetworks[$i]
            Password = $wifiPasswords[$i]
        }
    }
    $wifiInformation | Format-Table -AutoSize
    Write-Double $wifiInformation
    # OS Version, Installation Date
    $osVersion = Get-CimInstance Win32_OperatingSystem | Select-Object Version
    $installDate = Get-CimInstance Win32_OperatingSystem | Select-Object InstallDate
    Write-Double "`n"
    Write-Double "======= General System Information ======="
    Write-Double "Hardware Model: $($hardwareModel.Model)"
    Write-Double "BIOS/UEFI Version: $($biosVersion.Version)"
    Write-Double "`n======= RAM Information ======="
    # adapt size to human readable format
    $ramSlots | ForEach-Object { $_.Capacity = [math]::Round($_.Capacity / 1GB, 2) }
    $ramSlots | ForEach-Object { Write-Double "Slot: $($_.DeviceLocator), Size: $($_.Capacity) GB" }
    Write-Double "`n======= Processor Information ======="
    $processorInfoTable = $processorInfo | Format-Table -AutoSize | Out-String
    Write-Double $processorInfoTable

    Write-Double "`n======= Network Adapter Information ======="
    $networkAdaptersTable = $networkAdapters | Format-Table -AutoSize | Out-String
    Write-Double $networkAdaptersTable

    Write-Double "`n======= Hard Drive Information (GB) ======="
    $hardDrives | ForEach-Object { $_.Size = [math]::Round($_.Size / 1GB, 2) }
    $hardDrivesTable = $hardDrives | Format-Table -AutoSize | Out-String
    Write-Double $hardDrivesTable

    Write-Double "`n======= BitLocker Information ======="
    $bitlockerInfoTable = $bitlockerInfo | Format-Table -AutoSize | Out-String
    Write-Double $bitlockerInfoTable

    Write-Double "`n======= WiFi Network Information ======="
    foreach ($wifiInfo in $wifiInformation) {
        Write-Double "Network: $($wifiInfo.Network)"
        Write-Double "Password: $($wifiInfo.Password)`n"
    }
    Write-Double "`n======= OS Information ======="
    Write-Double "OS Version: $($osVersion.Version)"
    Write-Double "OS Installation Date: $($installDate.InstallDate)"
    Write-Double "========================================="
}

function ShowUserInformation { # Show user information
    # Display user account information
    Write-Double "`n======= User Account Information ======="
    $userAccounts = Get-WmiObject Win32_UserAccount
    foreach ($account in $userAccounts) {
        Write-Double "User Account: $($account.Caption)"
        Write-Double "SID: $($account.SID)"
        Write-Double "Full Name: $($account.FullName)"
        Write-Double "Description: $($account.Description)"
        Write-Double "Account Type: $($account.AccountType)"
        Write-Double "Disabled: $($account.Disabled)"
        Write-Double "Local Account: $($account.LocalAccount)"
        Write-Double "Lockout: $($account.Lockout)"
        Write-Double "Password Changeable: $($account.PasswordChangeable)"
        Write-Double "Password Expires: $($account.PasswordExpires)"
        Write-Double "Password Required: $($account.PasswordRequired)"
        Write-Double "Password Age: $($account.PasswordAge)`n"
    }

    # Display SAM database dump (This is just an example, and it requires proper permissions)
    Write-Double "`n======= SAM Database Dump ======="
    $samDump = Get-Content 'C:\Windows\System32\config\SAM' -Encoding Byte -Raw
    Write-Double "SAM Database Dump: $($samDump)`n"

    # Display GPO information
    Write-Host "`n======= GPO Information ======="
    try {
        $gpoInfo = Get-GPO -All
        foreach ($gpo in $gpoInfo) {
            Write-Double "GPO: $($gpo.DisplayName)"
            Write-Double "ID: $($gpo.Id.Guid)"
            Write-Double "Security Settings: $($gpo.SecurityDescriptor)"
            Write-Double "WMI Filter: $($gpo.WmiFilterId)"
            Write-Double "Creation Time: $($gpo.CreationTime)"
            Write-Double "Modification Time: $($gpo.ModificationTime)`n"
        }
    } catch {
        Write-Double "Error retrieving GPO information: $_`n"
    }

    # Verify UAC settings
    Write-Double "`n======= Verify UAC Settings ======="
    $uacSettings = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'
    Write-Double "UAC Settings - EnableLUA: $($uacSettings.EnableLUA)`n"

    Write-Double "`n========================================="
}

function ShowWindowsFirewallInformation {
    Write-Double "`n======= Windows Firewall Settings ======="
    
    # Check if the Windows Firewall service is running
    $firewallService = Get-Service -Name 'MpsSvc'
    if ($firewallService.Status -eq 'Running') {
        Write-Double "Windows Firewall Service is running.`n"

        # Check if the firewall is enabled
        $firewallStatus = Get-NetFirewallProfile | Select-Object Name, Enabled
        foreach ($profile in $firewallStatus) {
            Write-Double "`nFirewall Profile: $($profile.Name)"
            Write-Double "Enabled: $($profile.Enabled)"
        }

        # Display inbound and outbound rules
        Write-Double "`n======= Inbound Firewall Rules ======="
        $inboundRules = Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Inbound' } | Format-Table -AutoSize
        if ($inboundRules.Count -eq 0) {
            Write-Double "No Inbound Firewall Rules found.`n"
        } else {
            $inboundRules
        }

        Write-Double "`n======= Outbound Firewall Rules ======="
        $outboundRules = Get-NetFirewallRule | Where-Object { $_.Direction -eq 'Outbound' } | Format-Table -AutoSize
        if ($outboundRules.Count -eq 0) {
            Write-Double "No Outbound Firewall Rules found.`n"
        } else {
            $outboundRules
        }

        # CIS Recommendation: Ensure 'Windows Firewall: Public: Firewall state' is set to 'On' (1)
        $publicFirewallState = (Get-NetFirewallProfile -Name 'Public').Enabled
        if ($publicFirewallState -ne 1) {
            Write-Double "`nCIS Recommendation: Windows Firewall Public Profile should be set to 'On'.`n"
        }
    } else {
        Write-Double "`nWindows Firewall Service is not running.`n"
    }

    Write-Double "`n========================================="
}

function AutoDiscoverMinimizationServices {
    Write-Double "`n======= Auto-Discover Minimization Services ======="

    # Criteria for automatically adding services to the list
    $criteria = @{
        # Add criteria according to your needs
        'Status' = 'Running'  # Only running services
        'StartType' = 'Automatic'  # Only services with automatic start
    }

    # Get services that meet the criteria
    $servicesToStop = Get-Service | Where-Object {
        $matchesAll = $true
        foreach ($key in $criteria.Keys) {
            $matchesAll = $matchesAll -and $_.$key -eq $criteria[$key]
        }
        $matchesAll
    } | Select-Object -ExpandProperty Name

    foreach ($service in $servicesToStop) {
        $serviceStatus = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($serviceStatus -ne $null) {
            $color = 'White'  # Default color

            # Add additional conditions for highlighting as needed
            if ($serviceStatus.Status -eq 'Running') {
                $color = 'Red'  # Highlight running services
            }

            Write-Double "Service: $($serviceStatus.DisplayName)"
            Write-Double "Status: $($serviceStatus.Status)`n" -ForegroundColor $color
        } else {
            Write-Double "Service $service not found.`n"
        }
    }

    Write-Double "`n========================================="
}
function AuditCIS {  # Audit the system according to CIS
    $cisScriptPath = Join-Path $PSScriptRoot "cis.ps1"
    if (Test-Path $cisScriptPath) {
        & $cisScriptPath
    } else {
        Write-Double "Error: cis.ps1 not found at $cisScriptPath."
    }
}
function ResultToString($result) {  # Append result to global variable
    $global:results += $result
}

function ShowMenu { # Show menu
    Clear-Host
    Write-Host "Menu:"
    Write-Host "1. Show general information about the machine"
    Write-Host "2. Show user information"
    Write-Host "3. Show Windows Firewall information"
    Write-Host "4. Show minimization services"
    Write-Host "5. Audit the system according to CIS"
    Write-Host "O. Open results in Notepad"
    Write-Host "Q. Quit"
}

function ShowSubMenu1 { # Show submenu 1
    Write-Host "`nMenu:"
    Write-Host "1. Export (HTML)"
    Write-Host "2. Back"
}

# MAIN
# instantiate global variable
$global:results = @()

while ($true) {
    ShowMenu
    $choice = Read-Host "Enter your choice number"

    switch ($choice) {
        '1' {
            ShowGeneralInformation
            Pause
            break
        }
        '5' {
            AuditCIS
            break
        }
        '4' {
            AutoDiscoverMinimizationServices
            Pause
            break
        }
        '3' {
            ShowWindowsFirewallInformation
            Pause
            break
        }
        '2' {
            ShowUserInformation
            Pause
            break
        }
        'O' {
            $global:results | Out-File -FilePath 'results.txt'
            notepad 'results.txt'
            break
        }
        'Q' {
            Write-Host "Goodbye!"
            return
        }
        default {
            Write-Host "Invalid choice. Please enter a valid number."
            Start-Sleep -Seconds 2
        }
    }
}
