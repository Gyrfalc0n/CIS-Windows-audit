function ShowGeneralInformation { # Show general information about the machine
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
    # OS Version, Installation Date
    $osVersion = Get-CimInstance Win32_OperatingSystem | Select-Object Version
    $installDate = Get-CimInstance Win32_OperatingSystem | Select-Object InstallDate

    Write-Host "`n"
    Write-Host "======= General System Information ======="
    Write-Host "Hardware Model: $($hardwareModel.Model)"
    Write-Host "BIOS/UEFI Version: $($biosVersion.Version)"
    Write-Host "`n======= RAM Information ======="
    $ramSlots | ForEach-Object { Write-Host "Slot: $($_.DeviceLocator), Size: $($_.Capacity) bytes" }
    Write-Host "`n======= Processor Information ======="
    $processorInfo | Format-Table -AutoSize
    Write-Host "`n======= Network Adapter Information ======="
    $networkAdapters | Format-Table -AutoSize
    Write-Host "`n======= Hard Drive Information ======="
    $hardDrives | Format-Table -AutoSize
    Write-Host "`n======= BitLocker Information ======="
    $bitlockerInfo | Format-Table -AutoSize
    Write-Host "`n======= WiFi Network Information ======="
    for ($i = 0; $i -lt $wifiNetworks.Count; $i++) {
        Write-Host "Network: $($wifiNetworks[$i])"
        Write-Host "Password: $($wifiPasswords[$i])`n"
    }
    Write-Host "`n======= OS Information ======="
    Write-Host "OS Version: $($osVersion.Version)"
    Write-Host "OS Installation Date: $($installDate.InstallDate)"
    Write-Host "========================================="
}

function ExportInfoToHTML {
    # Collect information in an array of custom objects
    $informationArray = @()

    # Function to add information to the array
    function AddInformation($category, $name, $value) {
        $informationArray += [PSCustomObject]@{
            Category = $category
            Name = $name
            Value = $value
        }
    }

    # Hardware Model
    AddInformation('Hardware', 'Model', (Get-WmiObject Win32_ComputerSystem).Model)

    # BIOS or UEFI Version
    AddInformation('BIOS/UEFI', 'Version', (Get-WmiObject Win32_BIOS).Version)

    # Installed RAM slots, size of RAM on each slot
    $ramSlots = Get-WmiObject Win32_PhysicalMemory | Select-Object DeviceLocator, Capacity
    foreach ($ramSlot in $ramSlots) {
        AddInformation('RAM', $ramSlot.DeviceLocator, "$($ramSlot.Capacity) bytes")
    }

    # Information on the processor
    $processorInfo = Get-WmiObject Win32_Processor | Select-Object Name, MaxClockSpeed, NumberOfCores
    foreach ($property in $processorInfo.PSObject.Properties) {
        AddInformation('Processor', $property.Name, $property.Value)
    }

    # Network Adapter Characteristics, MAC/IP Addresses
    $networkAdapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true } | Select-Object Description, MACAddress, IPAddress
    foreach ($networkAdapter in $networkAdapters) {
        foreach ($property in $networkAdapter.PSObject.Properties) {
            AddInformation('Network Adapter', $property.Name, $property.Value)
        }
    }

    # Types and number of installed hard drives, BitLocker information
    $disks = Get-WmiObject Win32_DiskDrive | Select-Object MediaType, Size
    foreach ($disk in $disks) {
        foreach ($property in $disk.PSObject.Properties) {
            AddInformation('Hard Drive', $property.Name, $property.Value)
        }
    }

    $bitlockerInfo = Get-BitLockerVolume | Select-Object VolumeType, ProtectionStatus
    foreach ($property in $bitlockerInfo.PSObject.Properties) {
        AddInformation('BitLocker', $property.Name, $property.Value)
    }

    # Display known WiFi networks and their passwords
    $wifiNetworks = netsh wlan show profiles | Select-String "All User Profiles" | ForEach-Object {
        $_.ToString().Split(":")[1].Trim()
    }

    foreach ($wifiNetwork in $wifiNetworks) {
        $password = (netsh wlan show profile name=$wifiNetwork key=clear) -match "Key Content            : (.*)" | Out-Null; $matches[1]
        AddInformation('WiFi Network', "Network: $wifiNetwork", "Password: $password")
    }

    # Version of the OS, date of installation
    $osVersion = Get-CimInstance Win32_OperatingSystem | Select-Object Version
    $installDate = Get-CimInstance Win32_OperatingSystem | Select-Object InstallDate
    AddInformation('OS', 'Version', $osVersion.Version)
    AddInformation('OS', 'Install Date', $installDate.InstallDate)

    # Generate HTML content dynamically
    $htmlContent = "<html><head><style>`n table { border-collapse: collapse; width: 100%; } `n th, td { border: 1px solid black; padding: 8px; text-align: left; } `n th { background-color: #f2f2f2; } </style></head><body>`n<h1>General System Information</h1>"

    foreach ($info in $informationArray) {
        $htmlContent += "`n<h2>$($info.Category) Information</h2>`n<table>"
        $htmlContent += "<tr><th>$($info.Name)</th><td>$($info.Value)</td></tr>"
        $htmlContent += "</table>"
    }

    $htmlContent += "</body></html>"

    # Save HTML content to a file
    $exportFolder = Join-Path $PSScriptRoot "export"
    if (-not (Test-Path $exportFolder -PathType Container)) {
        New-Item -Path $exportFolder -ItemType Directory | Out-Null
    }

    $date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    $htmlFilePath = Join-Path $exportFolder "SystemInfo_$date.html"
    $htmlContent | Out-File -FilePath $htmlFilePath -Encoding UTF8 | Out-Null # Write to file

    Write-Host "General information exported to: $htmlFilePath"
}

function AuditCIS {  # Audit the system according to CIS
    $cisScriptPath = Join-Path $PSScriptRoot "cis.ps1"
    if (Test-Path $cisScriptPath) {
        & $cisScriptPath
    } else {
        Write-Host "Error: cis.ps1 not found at $cisScriptPath."
    }
}

function ShowMenu { # Show menu
    Clear-Host
    Write-Host "Menu:"
    Write-Host "1. Show general information about the machine"
    Write-Host "2. Audit the system according to CIS"
    Write-Host "Q. Quit"
}

function ShowSubMenu1 { # Show submenu 1
    Write-Host "`nMenu:"
    Write-Host "1. Export (HTML)"
    Write-Host "2. Back"
}

# MAIN
while ($true) {
    ShowMenu
    $choice = Read-Host "Enter your choice number"

    switch ($choice) {
        '1' {
            ShowGeneralInformation
            ShowSubMenu1
            $choice1 = Read-Host "Enter your choice number"
            switch ($choice1){
                '1' {
                    ExportInfoToHTML
                    Pause
                    break
                }
                '2' {
                    break
                }
                default {
                    Write-Host "Invalid choice. Please enter a valid number."
                    Start-Sleep -Seconds 2
                }
            }
            break
        }
        '2' {
            AuditCIS
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
