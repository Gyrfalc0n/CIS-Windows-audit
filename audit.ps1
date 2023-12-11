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
    Write-Host $wifiInformation
    # OS Version, Installation Date
    $osVersion = Get-CimInstance Win32_OperatingSystem | Select-Object Version
    $installDate = Get-CimInstance Win32_OperatingSystem | Select-Object InstallDate
    Write-Host "`n"
    Write-Host "======= General System Information ======="
    Write-Host "Hardware Model: $($hardwareModel.Model)"
    Write-Host "BIOS/UEFI Version: $($biosVersion.Version)"
    Write-Host "`n======= RAM Information ======="
    # adapt size to human readable format
    $ramSlots | ForEach-Object { $_.Capacity = [math]::Round($_.Capacity / 1GB, 2) }
    $ramSlots | ForEach-Object { Write-Host "Slot: $($_.DeviceLocator), Size: $($_.Capacity) GB" }
    Write-Host "`n======= Processor Information ======="
    $processorInfoTable = $processorInfo | Format-Table -AutoSize | Out-String
    Write-Host $processorInfoTable

    Write-Host "`n======= Network Adapter Information ======="
    $networkAdaptersTable = $networkAdapters | Format-Table -AutoSize | Out-String
    Write-Host $networkAdaptersTable

    Write-Host "`n======= Hard Drive Information (GB) ======="
    $hardDrives | ForEach-Object { $_.Size = [math]::Round($_.Size / 1GB, 2) }
    $hardDrivesTable = $hardDrives | Format-Table -AutoSize | Out-String
    Write-Host $hardDrivesTable

    Write-Host "`n======= BitLocker Information ======="
    $bitlockerInfoTable = $bitlockerInfo | Format-Table -AutoSize | Out-String
    Write-Host $bitlockerInfoTable

    Write-Host "`n======= WiFi Network Information ======="
    foreach ($wifiInfo in $wifiInformation) {
        Write-Host "Network: $($wifiInfo.Network)"
        Write-Host "Password: $($wifiInfo.Password)`n"
    }
    Write-Host "`n======= OS Information ======="
    Write-Host "OS Version: $($osVersion.Version)"
    Write-Host "OS Installation Date: $($installDate.InstallDate)"
    Write-Host "========================================="
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
            $informationArray = ShowGeneralInformation
            ShowSubMenu1
            $choice1 = Read-Host "Enter your choice number"
            switch ($choice1){
                '1' {
                    ExportInfoToHTML($informationArray)
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
