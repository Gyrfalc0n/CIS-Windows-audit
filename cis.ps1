# Set PowerShell execution policy
Set-ExecutionPolicy RemoteSigned -force

# CSS codes for report styling
$ReportStyle = @"
<title>System Audit Report: $env:computername</title>
<style>
    .report-title {
        font-family: Arial, Helvetica, sans-serif;
        color: #4242f9;
        font-size: 34px;
        text-align: center;
    }
    h1 {
        font-family: Arial, Helvetica, sans-serif;
        color: #4242f9;
        font-size: 28px;
    }
    h2 {
        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;
        padding-top: 10px;
    }
    table {
        font-size: 12px;
        border: 0px; 
        font-family: Arial, Helvetica, sans-serif;
        width: 100%;
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
    .status-warning {
        color: #ff0000;
    }
    .status-ok {
        color: #008000;
    }
    .hidden-panel {
        display: none;
    }
    .expand-button {
        font-size: 12px;
    }
</style>
"@


# Retrieve computer name
$SystemName = "<h1>System Name: $env:computername</h1>"

# Check for administrative privileges
Write-Host "Checking for administrative privileges..." -ForegroundColor DarkBlue
Start-Sleep -s 1
$isAdmin = ([System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    
if (!$isAdmin) {
    Write-Warning "Some operations require administrative privileges."
    Write-Warning "Please run the script with an administrative account."
    Read-Host "Press any key to continue..."
    exit
}

# Function to reverse SID from SecPol
Function Reverse-SID ($sidString) {
    # Processing and reversing SID
    # [Implementation of the function]
}

function BuildHTMLContent($ComplianceIndex,$ComplianceName,$CurrentValue, $ComplianceOrNot) {
	
    $ContentHTML	= "<tr ><td>$ComplianceIndex</td>"
    $ContentHTML	= "$ContentHTML <td>$ComplianceName</td>"
    $ContentHTML	= "$ContentHTML <td>$CurrentValue</td>"
    if ($ComplianceOrNot) {    
    $ContentHTML	= "$ContentHTML <td class='true'>Compliance</td>"
    Write-Host "       [+] "$ComplianceName -ForegroundColor Green 
    }
      else {
    $ContentHTML	= "$ContentHTML <td class='false'>Non Compliance</td>"
    Write-Host "       [-] "$ComplianceName -ForegroundColor Red
      }
    $ContentHTML	= "$ContentHTML </tr>"
    return $ContentHTML
    }

function GenerateHTMLContent($Index, $Name, $Value, $Compliant) {
    # Generating HTML content for each item
    # [Implementation of the function]
}

# Function to set registry value for compliance
function Set-RegistryCompliance($IsCompliant, $RegistryPath, $KeyName, $KeyValue) {
    if ($IsCompliant -eq $false) {
        $userResponse = Read-Host "Do you want to set compliance? [Y/N]: "
        if ($userResponse -eq "Y") {
            Set-ItemProperty -Path $RegistryPath -Name $KeyName -Value $KeyValue
        }
    }
}

# Function to convert an array of strings to a comma-separated list
function Convert-StringArrayToList($StringArray) {
    if ($StringArray) {
        $resultList = ""
        foreach ($item in $StringArray) {
            if ($resultList -ne "") { $resultList += "," }
            $resultList += $item
        }
        return $resultList
    } else {
        return ""
    }
}

# Function to generate HTML detail section
function Generate-HTMLDetailSection($Title, $Content) {
    $htmlSection = @"
    <TABLE>
        <tr>
            <th width='25%'><b>$Title</b></th>
            <td width='75%'>$Content</td>
        </tr>
    </TABLE>
"@
    return $htmlSection
}

# HTML block for tool details
$ToolInformation = @"
<div class='report-title'>System Audit Report</div>
<h2><center>Comprehensive Security Analysis</center></h2>
<hr>
"@

# Retrieve and format the current date
$CurrentDate = Get-Date -Format "ddMMyyyy"
$AuditFileName = "audit_" + $CurrentDate + ".txt"

# Audit directory setup
Write-Host "Creating Audit directory..." -ForegroundColor DarkGreen
$AuditDirectory = "Audit_" + $CurrentDate
Remove-Item $AuditDirectory -Recurse -ErrorAction Ignore
New-Item -ItemType Directory -Name $AuditDirectory | Out-Null
Set-Location $AuditDirectory

# Gather OS information
$OSDetails = Get-WmiObject Win32_OperatingSystem | Select-Object Caption, Version, ServicePackMajorVersion, OSArchitecture, CSName, WindowsDirectory, NumberOfUsers, BootDevice
$OSVersion = $OSDetails.Caption
$MachineName = $OSDetails.CSName
$Architecture = $OSDetails.OSArchitecture

# Output OS information to file
Write-Host "Collecting Server Information..." -ForegroundColor DarkGreen
"##### System Information #####" > $AuditFileName
"OS Version: $OSVersion" >> $AuditFileName
"Machine Name: $MachineName" >> $AuditFileName
"Architecture: $Architecture" >> $AuditFileName

# Prepare for audit
"##### System Audit #####" >> $AuditFileName
$TestIndex = 1

# Collect important files for analysis
Write-Host "Collecting files for analysis..." -ForegroundColor DarkGreen
$SeceditFile = "./secpol_" + $MachineName + ".cfg"
secedit /export /cfg $SeceditFile | Out-Null
$GPOFileTxt = "./gpo_" + $MachineName + ".txt"
gpresult /r /V > $GPOFileTxt | Out-Null
$GPOFileHtml = "./gpo_" + $MachineName + ".html"
gpresult /h $GPOFileHtml /f | Out-Null


# Command to backup audit configuration
$BackupAuditConfigFile = "./backup_auditpolicy_" + $MachineName + ".txt"
auditpol.exe /get /Category:* > $BackupAuditConfigFile | Out-Null

# Retrieve and convert OS information to HTML
$OSDetailsHTML = Get-CimInstance -Class Win32_OperatingSystem | ConvertTo-Html -As List -Property Version, Caption, OSArchitecture, CSName, BuildNumber, Manufacturer -Fragment -PreContent "<h2>SYSTEM OS DETAILS</h2>"

# Retrieve and convert Processor information to HTML
$ProcessorDetailsHTML = Get-CimInstance -ClassName Win32_Processor | ConvertTo-Html -As List -Property DeviceID, Name, Caption, MaxClockSpeed, SocketDesignation, Manufacturer -Fragment -PreContent "<h2>PROCESSOR DETAILS</h2>"

# Retrieve and convert BIOS information to HTML
$BiosDetailsHTML = Get-CimInstance -ClassName Win32_BIOS | ConvertTo-Html -As List -Property SMBIOSBIOSVersion, Manufacturer, Name, SerialNumber -Fragment -PreContent "<h2>BIOS DETAILS</h2>"

# Retrieve disk details and convert to HTML
$DiskInfoCollection = Get-CimInstance -ClassName Win32_LogicalDisk | Where {$_.DriveType -eq 3} | Select-Object DeviceID, VolumeName, ProviderName, FileSystem, @{Name="Size (MB)"; Expression={[math]::round($_.size / 1MB)}}, @{Name="Free Space (MB)"; Expression={[math]::round($_.FreeSpace / 1MB)}}, @{Name="Free Space (%)"; Expression={[Math]::Round($_.FreeSpace / $_.Size * 100)}}
$DiskDetailsHTML = $DiskInfoCollection | ConvertTo-Html -Fragment -PreContent "<h2>DISK DETAILS</h2>"

# Retrieve and convert network adapter configuration to HTML
$NetworkConfigCollection = Get-WmiObject -ClassName Win32_NetworkAdapterConfiguration | Where {$_.IPEnabled} | Select-Object Description, MACAddress, @{Name="IP Address / Subnet Mask"; Expression={if ($_.IPAddress -ne $Null) { "$($_.IPAddress)/$($_.IPSubnet)" }}}, @{Name="Default Gateway"; Expression={$_.DefaultIPGateway}}, @{Name="DHCP Enabled"; Expression={if ($_.DHCPEnabled) {"Yes"} else {"No"}}}, @{Name="DNS Servers"; Expression={$_.DNSServerSearchOrder}}, @{Name="WINS Servers"; Expression={"$($_.WINSPrimaryServer) $($_.WINSSecondaryServer)"}}
$NetworkDetailsHTML = $NetworkConfigCollection | ConvertTo-Html -Fragment -PreContent "<h2>NETWORK CONFIGURATION</h2>"

# Retrieve service information and convert to HTML
$ServiceReportFile = "./Services_Report_" + $MachineName + ".html"
$ServiceDetails = Get-CimInstance -ClassName Win32_Service | ConvertTo-Html -Property Name, DisplayName, State -Fragment -PreContent "<h2>SERVICE DETAILS for $MachineName</h2>" > $ServiceReportFile
$ServiceDetailsEnhanced = Get-CimInstance -ClassName Win32_Service | ConvertTo-Html -Property Name, DisplayName, State -Fragment -PreContent "<h2 class='accordion'>SERVICES DETAILS<span class='expando'> [ show ]</span></h2><div class='panel'>" -PostContent "</div>"
$ServiceDetailsEnhanced = $ServiceDetailsEnhanced -replace '<td>Running</td>', '<td class="RunningStatus">Running</td>' -replace '<td>Stopped</td>', '<td class="StopStatus">Stopped</td>'

# Retrieve and convert local share information to HTML
$LocalShareDetailsHTML = Get-CimInstance -ClassName Win32_Share | ConvertTo-Html -Property Name, Caption, Path -Fragment -PreContent "<h2>LOCAL SHARES DETAILS</h2>"

# Retrieve and convert printer information to HTML
$PrinterDetailsHTML = Get-CimInstance -ClassName Win32_Printer | ConvertTo-Html -Property Name, Location -Fragment -PreContent "<h2>PRINTER DETAILS</h2>"

# Retrieve and convert local account information to HTML
$LocalAccountReportFile = "LocalAccounts_" + $MachineName + ".html"
$LocalAccountDetails = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object Caption, Status, PasswordExpires, AccountType, Description, Disabled, Domain, FullName, InstallDate, LocalAccount, Lockout, Name, PasswordChangeable, PasswordRequired, SID, SIDType | ConvertTo-Html -Property Name, Caption, Disabled, Description -PreContent "<h2>LOCAL ACCOUNTS DETAILS</h2>"
$LocalAccountDetails > $LocalAccountReportFile
$LocalAccountDetailsEnhanced = $LocalAccountDetails -replace '<td>True</td>', '<td class="true">True</td>' -replace '<td>False</td>', '<td class="false">False</td>'

# Compliance report HTML header
$ComplianceReportHeader = '<h2>COMPLIANCE STATUS OVERVIEW</h2>'

Write-Host "EVALUATING SECURITY BENCHMARKS" -ForegroundColor Green 
Start-Sleep -Seconds 2
$BenchmarkIndex = 0
$SecurityReportHTML = "$SecurityReportHTML <table > <tbody><th width='5%'>Index</th><th width='50%'>Criterion</th><th width='30%'>Current Setting</th><th width='15%'>Status</th></tbody><tbody>"

# Assess Password Policy
Write-Host "`n [+] Starting Password Policy Analysis`n" -ForegroundColor DarkGreen
Start-Sleep -Seconds 1

# Enforce Password History Check
$BenchmarkIndex += 1 
$AnalysisResult = $null
$CriterionName		= "Verify 'Enforce password history' is '24 or more'"
$AnalysisResult		= Get-Content $SecurityConfigFile | Select-String "PasswordHistorySize" 
$CurrentValue	= $AnalysisResult 
$AnalysisResult 	= $AnalysisResult  -replace "[^0-9]" , ''
$IsCompliant	= ($AnalysisResult  -ge "24") 
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Maximum Password Age Check
$BenchmarkIndex += 1 
$AnalysisResult = $null
$CriterionName		= "Check 'Maximum password age' is '60 days or fewer'"
$AnalysisResult		= Get-Content $SecurityConfigFile | Select-String "MaximumPasswordAge" | Select-Object -First 1 
$CurrentValue	= $AnalysisResult 
$AnalysisResult 	= $AnalysisResult  -replace "[^0-9]" , ''
$IsCompliant	= ([int]$AnalysisResult  -gt 0) -and ($AnalysisResult  -le 60)
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Minimum Password Age Check
$BenchmarkIndex += 1 
$AnalysisResult = $null
$CriterionName		= "Verify 'Minimum password age' is '1 day or more'"
$AnalysisResult		= Get-Content $SecurityConfigFile | Select-String "MinimumPasswordAge"
$CurrentValue	= $AnalysisResult 
$AnalysisResult 	= $AnalysisResult  -replace "[^0-9]" , ''
$IsCompliant	= ($AnalysisResult  -ge "1") 
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Additional compliance checks continue...

# Account Lockout Policy Evaluation
Write-Host "`n [+] Starting Account Lockout Policy Analysis`n" -ForegroundColor DarkGreen
Start-Sleep -Seconds 1

# Account Lockout Duration Check
$BenchmarkIndex += 1 
$AnalysisResult = $null
$CriterionName		= "Ensure 'Account lockout duration' is '15 minutes or more'"
$AnalysisResult		= Get-Content $AccountPolicyFile | Select-String -pattern 'Lockout duration'
$CurrentValue	= $AnalysisResult 
$AnalysisResult 	= $AnalysisResult  -replace "[^0-9]" , ''
$IsCompliant	= ($AnalysisResult  -ge "15") 
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Evaluate Reset Account Lockout Counter
$BenchmarkIndex += 1 
$EvaluationResult = $null
$CriterionName		= "Verify 'Reset account lockout counter after' is '15 minutes or more'"
$EvaluationResult	= Get-Content $NetworkPolicyFile | Select-String -Pattern "Lockout observation window"
$CurrentValue	= $EvaluationResult 
$EvaluationResult 	= $EvaluationResult -replace "[^0-9]" , ''
$IsCompliant	= ($EvaluationResult -ge "15") 
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# User Rights Assignment Audit
Write-Host "`n [+] Initiating User Rights Assignment Analysis `n" -ForegroundColor DarkGreen
Start-Sleep -Seconds 1

# Check Access Credential Manager as a Trusted Caller
$BenchmarkIndex += 1 
$EvaluationResult = $null
$CriterionName		= "Check 'Access Credential Manager as a trusted caller' is set to 'No One'"
$EvaluationResult	= Get-Content $SecurityConfigFile | Select-String "SeTrustedCredManAccessPrivilege"
$CurrentValue	= $EvaluationResult 
$IsCompliant	= -Not($EvaluationResult -match "SeTrustedCredManAccessPrivilege") 
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Access This Computer from the Network
$BenchmarkIndex += 1 
$EvaluationResult = $null
$CriterionName		= "Ensure 'Access this computer from the network' includes only 'Administrators, Remote Desktop Users'"
$SIDChain = Get-Content $SecurityConfigFile | Select-String "SeNetworkLogonRight" 
$SIDChain = $SIDChain.line
$EvaluationResult = ConvertSIDToString $SIDChain
$CurrentValue	= $EvaluationResult 
$IsCompliant	= ($EvaluationResult -notmatch "Everyone") 
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Act as Part of the Operating System
$BenchmarkIndex += 1 
$EvaluationResult = $null
$CriterionName		= "Verify 'Act as part of the operating system' is set to 'No One'"
$SIDChain = Get-Content $SecurityConfigFile | Select-String "SeTcbPrivilege"
$SIDChain = $SIDChain.line
$EvaluationResult = ConvertSIDToString $SIDChain
$CurrentValue	= $EvaluationResult 
$IsCompliant	= ($EvaluationResult.Length -eq 0)
$SecurityReportHTML += GenerateHTMLReport $BenchmarkIndex $CriterionName $CurrentValue $IsCompliant

# Evaluate Memory Quotas for Processes
$SecurityIndex += 1 
$ProcessEvaluation = $null
$PolicyName		= "Check 'Adjust memory quotas for a process' includes 'Administrators, LOCAL SERVICE, NETWORK SERVICE'"
$SIDSequence = Get-Content $SecurityPolicyFile | Select-String "SeIncreaseQuotaPrivilege"
$SIDSequence = $SIDSequence.line
$ProcessEvaluation = TranslateSID $SIDSequence
$EvaluatedValue	= $ProcessEvaluation 
$PolicyCompliance	= (($ProcessEvaluation -match "Administrators")-and ($ProcessEvaluation -match "LOCAL SERVICE") -and ($ProcessEvaluation -match "NETWORK SERVICE"))
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

# Validate Local Logon Permissions
$SecurityIndex += 1 
$ProcessEvaluation = $null
$PolicyName		= "Verify 'Allow log on locally' is configured for 'Administrators, Users'"
$SIDSequence = Get-Content $SecurityPolicyFile | Select-String "SeInteractiveLogonRight"
$SIDSequence = $SIDSequence.line
$ProcessEvaluation = TranslateSID $SIDSequence
$EvaluatedValue	= $ProcessEvaluation 
$PolicyCompliance	= (($ProcessEvaluation -match "Administrators") -and ($ProcessEvaluation -notmatch "Guest")  -and ($ProcessEvaluation -notmatch "Everyone"))
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

# Remote Desktop Services Logon Check
$SecurityIndex += 1 
$ProcessEvaluation = $null
$PolicyName		= "Ensure 'Allow log on through Remote Desktop Services' includes 'Administrators, Remote Desktop Users'"
$SIDSequence = Get-Content $SecurityPolicyFile | Select-String "SeRemoteInteractiveLogonRight"
$SIDSequence = $SIDSequence.line
$ProcessEvaluation = TranslateSID $SIDSequence
$EvaluatedValue	= $ProcessEvaluation 
$PolicyCompliance	= (($ProcessEvaluation -match "Administrators") -and ($ProcessEvaluation -match "Remote Desktop Users") -and ($ProcessEvaluation -notmatch "Guest") ) 
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

# Backup Files and Directories Policy
$SecurityIndex += 1 
$ProcessEvaluation = $null
$PolicyName		= "Check 'Back up files and directories' is restricted to 'Administrators'"
$SIDSequence = Get-Content $SecurityPolicyFile | Select-String "SeBackupPrivilege"
$SIDSequence = $SIDSequence.line
$ProcessEvaluation = TranslateSID $SIDSequence
$EvaluatedValue	= $ProcessEvaluation 
$PolicyCompliance	= (($ProcessEvaluation -match "Administrators") -and ($ProcessEvaluation.Length -lt 30)) 
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

#Check Change the system time
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Make sure 'Change the system time' is set to 'Administrators, LOCAL SERVICE'"
$chaineSID = Get-Content $seceditFile |Select-String "SeSystemtimePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -notmatch "autotimesvc")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Change the time zone
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Make sure 'Change the time zone' is set to 'Administrators, LOCAL SERVICE'"
$chaineSID = Get-Content $seceditFile |Select-String "SeTimeZonePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE") -and ($traitement  -notmatch "Users") -and ($traitement  -notmatch "Guest")  -and ($traitement  -notmatch "Everyone")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Create a pagefile
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Create a pagefile' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeCreatePagefilePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Create a token object
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Create a token object' is set to 'No One'"
$chaineSID = Get-Content $seceditFile |Select-String "SeCreateTokenPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0)
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Create global objects
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
$chaineSID = Get-Content $seceditFile |Select-String "SeCreateGlobalPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE")  -and ($traitement  -match "SERVICE")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Create permanent shared objects
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Create permanent shared objects' is set to 'No One'"
$chaineSID = Get-Content $seceditFile |Select-String "SeCreatePermanentPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0)
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Create symbolic links
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Create symbolic links'  is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeCreateSymbolicLinkPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Debug programs
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Debug programs' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeDebugPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Deny access to this computer from the network
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Deny access to this computer from the network' to include 'Guests, Local account'"
$chaineSID = Get-Content $seceditFile |Select-String "SeDenyNetworkLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest") -and ($traitement  -match "Local account")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Deny log on as a batch job
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Deny log on as a batch job' to include 'Guests'"
$chaineSID = Get-Content $seceditFile |Select-String "SeDenyBatchLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Deny log on as a service
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Deny log on as a service' to include 'Guests'"
$chaineSID = Get-Content $seceditFile |Select-String "SeDenyServiceLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Deny log on locally
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Deny log on locally' to include 'Guests'"
$chaineSID = Get-Content $seceditFile |Select-String "SeDenyInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Deny logon through Remote Desktop Services
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Deny logon through Remote Desktop Services' to include 'Guests, Local account'"
$chaineSID = Get-Content $seceditFile |Select-String "SeDenyRemoteInteractiveLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Guest") -and ($traitement  -match "Local account")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Enable computer and user accounts to be trusted for delegation
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'"
$chaineSID = Get-Content $seceditFile |Select-String "SeEnableDelegationPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement.Length -eq 0)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Force shutdown from a remote system
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Force shutdown from a remote system' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeRemoteShutdownPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement.Length -lt 30)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Generate security audits
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
$chaineSID = Get-Content $seceditFile |Select-String "SeAuditPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "LOCAL SERVICE")  -and ($traitement  -match "NETWORK SERVICE"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Impersonate a client after authentication
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'"
$chaineSID = Get-Content $seceditFile |Select-String "SeImpersonatePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "LOCAL SERVICE")  -and ($traitement  -match "NETWORK SERVICE")-and ($traitement  -match "NT AUTHORITY\\SERVICE"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Increase scheduling priority
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'"
$chaineSID = Get-Content $seceditFile |Select-String "SeIncreaseBasePriorityPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "Window Manager\\Window Manager Group"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Load and unload device drivers
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Load and unload device drivers' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeLoadDriverPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Lock pages in memory
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Lock pages in memory' is set to 'No One'"
$chaineSID = Get-Content $seceditFile |Select-String "SeLockMemoryPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Log on as a batch job
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Log on as a batch job' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeBatchLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Log on as a service
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Configure 'Log on as a service'"
$chaineSID = Get-Content $seceditFile |Select-String "SeServiceLogonRight"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Manage auditing and security log
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Manage auditing and security log' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeSecurityPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Modify an object label
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Modify an object label' is set to 'No One'"
$chaineSID = Get-Content $seceditFile |Select-String "SeRelabelPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= ($traitement.Length -eq 0) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Modify firmware environment values
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Modify firmware environment values' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeSystemEnvironmentPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Perform volume maintenance tasks
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Perform volume maintenance tasks' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeManageVolumePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Profile single process
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Profile single process' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeProfileSingleProcessPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Profile system performance
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'"
$chaineSID = Get-Content $seceditFile |Select-String "SeSystemProfilePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators") -and ($traitement  -match "NT SERVICE\\WdiServiceHost"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Replace a process level token
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'"
$chaineSID = Get-Content $seceditFile |Select-String "SeAssignPrimaryTokenPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "LOCAL SERVICE") -and ($traitement  -match "NETWORK SERVICE"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Restore files and directories
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Restore files and directories' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeRestorePrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Shut down the system
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Shut down the system' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeShutdownPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Take ownership of files or other objects
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Take ownership of files or other objects' is set to 'Administrators'"
$chaineSID = Get-Content $seceditFile |Select-String "SeTakeOwnershipPrivilege"
$chaineSID = $chaineSID.line
$traitement = Reverse-SID $chaineSID
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Administrators")-and ($traitement.Length -lt 30))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check lock out policy
Write-Host "`n [+] Begin Security Options Audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1

$ListLocalUser = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'"
foreach ( $user in $ListLocalUser) {
  if ( $user.sid -like "*-500") {
    $adminName = $user.Name
    $adminStatus = $user.Disabled
    if ($adminStatus -eq $true) {
      $adminStatus = "Disabled"
    }
    else {
      $adminStatus = "Enabled"
    }
  }
  elseif ( $user.sid -like "*-501") {
    $guestName = $user.Name
    $guestStatus = $user.Disabled
    if ($guestStatus -eq $true) {
      $guestStatus = "Disabled"
    }
    else {
      $guestStatus = "Enabled"
    }

  }

}

#Check Accounts: Administrator account status
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Accounts: Administrator account status' is set to 'Disabled'"
$traitement = $adminStatus
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Disabled"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Block Microsoft accounts
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path | Select-Object NoConnectedUser
  $traitement = $traitement.NoConnectedUser
  if($traitement -eq $null){
	  $traitement  = "5"
  }
}else{

  $traitement = "2"
}
$data = @("This policy is disabled","Users can't add Microsoft accounts","XXX","Users can't add or log on with Microsoft accounts", "Not Configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "3"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Guest account status
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Ensure 'Accounts: Guest account status' is set to 'Disabled'"
$traitement = $guestStatus
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -match "Disabled"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Accounts: Limit local account use of blank passwords to console logon only
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LimitBlankPasswordUse
  $traitement = $traitement.LimitBlankPasswordUse
}else{

  $traitement = "2"
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Rename administrator account
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Configure 'Accounts: Rename administrator account'"
$traitement = $adminName
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -notmatch "Administrator"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Accounts: Rename guest account
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName		= "Configure 'Accounts: Rename guest account'"
$traitement = $guestName
$CurrentValue	= $traitement 
$ComplianceOrNot	= (($traitement  -notmatch "Guest"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Audit: Force audit policy subcategory settings (Windows Vista or later)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object SCENoApplyLegacyAuditPolicy
  $traitement = $traitement.SCENoApplyLegacyAuditPolicy
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Audit: Shut down system immediately if unable to log security audits
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'"
$exist =  Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object CrashOnAuditFail
  $traitement = $traitement.CrashOnAuditFail
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Devices: Allowed to format and eject removable media
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Devices: Allowed to format and eject removable media' is set to 'Administrators and Interactive Users'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AllocateDASD
  $traitement = $traitement.AllocateDASD
  if($traitement -eq $null){
	  $traitement  = "3"
  }
}
$data = @("Administrators","Administrators and Power Users","Administrators and Interactive Users","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "2"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Devices: Prevent users from installing printer drivers
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AddPrinterDrivers
  $traitement = $traitement.AddPrinterDrivers
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Domain member: Digitally encrypt or sign secure channel data (always)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object RequireSignOrSeal
  $traitement = $traitement.RequireSignOrSeal
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Domain member: Digitally encrypt secure channel data (when possible)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object SealSecureChannel
  $traitement = $traitement.SealSecureChannel
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Domain member: Digitally sign secure channel data (when possible)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object SignSecureChannel
  $traitement = $traitement.SignSecureChannel
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Domain member: Disable machine account password changes
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Domain member: Disable machine account password changes' is set to 'Disabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DisablePasswordChange
  $traitement = $traitement.DisablePasswordChange
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Domain member: Disable machine account password changes
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Domain member: Maximum machine account password age' is set to '30 or fewer days, but not 0'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object MaximumPasswordAge
  $traitement = $traitement.MaximumPasswordAge  
}
$CurrentValue	= $traitement 
$ComplianceOrNot	= (([int]$traitement  -gt 0) -and ([int]$traitement  -le 30 ))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Domain member: Require strong (Windows 2000 or later) session key
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object RequireStrongKey
  $traitement = $traitement.RequireStrongKey
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot



#Check Interactive logon: Do not require CTRL+ALT+DEL
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DisableCAD
  $traitement = $traitement.DisableCAD
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Interactive logon: Don't display last signed-in
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Don't display last signed-in' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object dontdisplaylastusername
  $traitement = $traitement.dontdisplaylastusername
  if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Interactive logon: Machine account lockout threshold
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object MaxDevicePasswordFailedAttempts
  $traitement = $traitement.MaxDevicePasswordFailedAttempts
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -gt 0) -and ([int]$traitement  -le 10 ))   
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Interactive logon: Machine inactivity limit
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Machine inactivity limit' is set to '900 or fewer second(s), but not 0'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object InactivityTimeoutSecs
  $traitement = $traitement.InactivityTimeoutSecs
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -gt 0) -and ([int]$traitement  -le 900 ))   
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Interactive logon: Message text for users attempting to log on
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Configure 'Interactive logon: Message text for users attempting to log on'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object legalnoticetext
  $traitement = $traitement.legalnoticetext
}else{

  $traitement = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement.Length  -gt 0))   
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Interactive logon: Number of previous logons to cache (in case domain controller is not available)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Number of previous logons to cache (in case domain controller is not available)' is set to '4 or fewer'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object CachedLogonsCount
  $traitement = $traitement.CachedLogonsCount
  if($traitement -eq $null){
	  $traitement  = "10"
  }
}
$CurrentValue	= $traitement 
$ComplianceOrNot	= (([int]$traitement  -ge 0) -and ([int]$traitement  -le 4 ))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Interactive logon: Prompt user to change password before expiration
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Prompt user to change password before expiration' is set to 'between 5 and 14 days'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object PasswordExpiryWarning
  $traitement = $traitement.PasswordExpiryWarning
  if($traitement -eq $null){
	  $traitement  = "15"
  }
}
$CurrentValue	= $traitement 
$ComplianceOrNot	= (([int]$traitement  -ge 5) -and ([int]$traitement  -le 14 ))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Interactive logon: Prompt user to change password before expiration
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Interactive logon: Smart card removal behavior' is set to 'Lock Workstation' or higher"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ScRemoveOption
  $traitement = $traitement.ScRemoveOption
}
$data = @("No Action","Lock Workstation","Force Logoff","Disconnect if a remote Remote Desktop Services session")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (([int]$traitement  -ge 1))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot



#Check Microsoft network client: Digitally sign communications (always)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network client: Digitally sign communications (always)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object RequireSecuritySignature
  $traitement = $traitement.RequireSecuritySignature
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Microsoft network client: Digitally sign communications (if server agrees)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network client: Digitally sign communications (if server agrees)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableSecuritySignature
  $traitement = $traitement.EnableSecuritySignature
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Microsoft network client: Send unencrypted password to third-party SMB servers
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network client: Send unencrypted password to third-party SMB servers' is set to 'Disabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnablePlainTextPassword
  $traitement = $traitement.EnablePlainTextPassword
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Microsoft network server: Amount of idle time required before suspending session
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network server: Amount of idle time required before suspending session' is set to '15 or fewer minute(s)'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AutoDisconnect
  $traitement = $traitement.AutoDisconnect
	if($traitement -eq $null){
	  $traitement  = "999"
  }
}
$CurrentValue	= $traitement 
$ComplianceOrNot	= (([int]$traitement  -ge 0) -and ([int]$traitement  -le 15 ))
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Microsoft network server: Digitally sign communications (always)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network server: Digitally sign communications (always)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object RequireSecuritySignature
  $traitement = $traitement.RequireSecuritySignature
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Microsoft network server: Digitally sign communications (if client agrees)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network server: Digitally sign communications (if client agrees)' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableSecuritySignature
  $traitement = $traitement.EnableSecuritySignature
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Microsoft network server: Disconnect clients when logon hours expire
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network server: Disconnect clients when logon hours expire' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableForcedLogoff
  $traitement = $traitement.EnableForcedLogoff
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check Microsoft network server: Server SPN target name validation level
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Microsoft network server: Server SPN target name validation level' is set ' is set to 'Accept if provided by client' or higher"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object SmbServerNameHardeningLevel
  $traitement = $traitement.SmbServerNameHardeningLevel
	if($traitement -eq $null){
	  $traitement  = "3"
  }
}
$data = @("Off","Accept if provided by client","Required from client","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (([int]$traitement  -eq 1) -or ([int]$traitement  -eq 2))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

# Validate Anonymous SID/Name Translation Settings
$SecurityIndex += 1 
$EvaluationProcess = $null
$PolicyName = "Validate 'Network access: Allow anonymous SID/Name translation' is 'Disabled'"
$EvaluationProcess = Get-Content $SecurityConfigFile | Select-String "LSAAnonymousNameLookup"
$EvaluatedValue = $EvaluationProcess 
$EvaluationProcess = $EvaluationProcess -replace "[^0-9]", ''
$PolicyCompliance = ($EvaluationProcess -eq "0") 
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

# Ensure No Anonymous Enumeration of SAM Accounts
$SecurityIndex += 1 
$EvaluationProcess = $null
$PolicyName = "Check 'Network access: Do not allow anonymous enumeration of SAM accounts' is 'Enabled'"
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$RegistryExistence = Test-Path $RegistryPath
if ($RegistryExistence -eq $true) {
  $EvaluationProcess = Get-ItemProperty $RegistryPath | Select-Object RestrictAnonymousSAM
  $EvaluationProcess = $EvaluationProcess.RestrictAnonymousSAM
  if($EvaluationProcess -eq $null){
    $EvaluationProcess = "2"
  }
}
$StatusOptions = @("Disabled", "Enabled", "Not Configured")
$EvaluatedValue = $StatusOptions[[int]$EvaluationProcess]
$PolicyCompliance = ($EvaluationProcess -match "1")  
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

# Verify SAM Accounts and Shares Enumeration Settings
$SecurityIndex += 1 
$EvaluationProcess = $null
$PolicyName = "Confirm 'Network access: Do not allow anonymous enumeration of SAM accounts and shares' is 'Enabled'"
$RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$RegistryExistence = Test-Path $RegistryPath
if ($RegistryExistence -eq $true) {
  $EvaluationProcess = Get-ItemProperty $RegistryPath | Select-Object RestrictAnonymous
  $EvaluationProcess = $EvaluationProcess.RestrictAnonymous
  if($EvaluationProcess -eq $null){
    $EvaluationProcess = "2"
  }
}
$StatusOptions = @("Disabled", "Enabled", "Not Configured")
$EvaluatedValue = $StatusOptions[[int]$EvaluationProcess]
$PolicyCompliance = ($EvaluationProcess -match "1")  
$ComplianceDetailsHTML += BuildHTMLContent $SecurityIndex $PolicyName $EvaluatedValue $PolicyCompliance

$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Do not allow storage of passwords and credentials for network authentication' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DisableDomainCreds
  $traitement = $traitement.DisableDomainCreds
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Let Everyone permissions apply to anonymous users
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Let Everyone permissions apply to anonymous users' is not set to 'Disabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EveryoneIncludesAnony
  $traitement = $traitement.EveryoneIncludesAnony
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Named Pipes that can be accessed anonymously
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Named Pipes that can be accessed anonymously' is set to 'None'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object NullSessionPipes
  $traitement = $traitement.NullSessionPipes
}else{

  $traitement = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement.Length  -eq 0) -or ($traitement.Length  -lt 5)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Remotely accessible registry paths
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Remotely accessible registry paths' is set"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedExactPaths"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object Machine
  $traitement = $traitement.Machine
}else{

  $traitement = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -match "ProductOptions") -and ($traitement  -match "ProductOptions")-and ($traitement  -match "ProductOptions")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Remotely accessible registry paths and sub-paths
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Remotely accessible registry paths and sub-paths' is set"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object Machine
  $traitement = $traitement.Machine
}else{

  $traitement = ""
}
$regPath =@("System\\CurrentControlSet\\Control\\Print\\Printers","System\\CurrentControlSet\\Services\\Eventlog",
"SOFTWARE\\Microsoft\\OLAP Server","SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Print","SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
"System\\CurrentControlSet\\Control\\ContentIndex","System\\CurrentControlSet\\Control\\Terminal Server","System\\CurrentControlSet\\Control\\Terminal Server\\UserConfig",
"System\\CurrentControlSet\\Control\\Terminal Server\\DefaultUserConfiguration","SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Perflib","System\\CurrentControlSet\\Services\\SysmonLog"
)
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -match $regPath[0]) -and ($traitement  -match $regPath[1])-and ($traitement  -match $regPath[2])-and ($traitement  -match $regPath[3])-and
						($traitement  -match $regPath[3])-and ($traitement  -match $regPath[4])-and ($traitement  -match $regPath[5])-and ($traitement  -match $regPath[6])-and 
						($traitement  -match $regPath[7])-and ($traitement  -match $regPath[8])-and ($traitement  -match $regPath[9])-and ($traitement  -match $regPath[10])) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Restrict anonymous access to Named Pipes and Shares
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Restrict anonymous access to Named Pipes and Shares' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object RestrictNullSessAccess
  $traitement = $traitement.RestrictNullSessAccess
	if($traitement -eq $null){
	  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Restrict clients allowed to make remote calls to SAM
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Restrict clients allowed to make remote calls to SAM' is set to 'Administrators: Remote Access: Allow'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object RestrictRemoteSAM
  $traitement = $traitement.RestrictRemoteSAM
	if($traitement -eq $null){
	  $traitement  = "Not Defined"
  }
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -eq "O:BAG:BAD:(A;;RC;;;BA)"))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Shares that can be accessed anonymously
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Shares that can be accessed anonymously' is set to 'None'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object NullSessionShares
  $traitement = $traitement.NullSessionShares
  if($traitement -eq $null){
	  $traitement  = ""
  }
}else{

  $traitement = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement.Length  -eq 0)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network access: Sharing and security model for local accounts
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network access: Sharing and security model for local accounts' is set to 'Classic - local users authenticate as themselves'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ForceGuest
  $traitement = $traitement.ForceGuest
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Classic - local users authenticate as themselves","Guest only - local users authenticate as Guest","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: Allow Local System to use computer identity for NTLM
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network security: Allow Local System to use computer identity for NTLM' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object UseMachineId
  $traitement = $traitement.UseMachineId
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: Allow LocalSystem NULL session fallback
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network security: Allow LocalSystem NULL session fallback' is set to 'Disabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AllowNullSessionFallback
  $traitement = $traitement.AllowNullSessionFallback
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network Security: Allow PKU2U authentication requests to this computer to use online identities
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network Security: Allow PKU2U authentication requests to this computer to use online identities' is set to 'Disabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AllowOnlineID
  $traitement = $traitement.AllowOnlineID
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: Configure encryption types allowed for Kerberos
$ComplianceIndex += 1
$traitement = $null
$ComplianceName = "Ensure 'Network security: Configure encryption types allowed for Kerberos' is set to 'AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object SupportedEncryptionTypes
  $traitement = $traitement.SupportedEncryptionTypes
  if($traitement -eq $null){
	  $traitement  = "Not Defined"
  }
}else{
	$traitement  = "Not Defined"
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -eq 2147483640))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: Do not store LAN Manager hash value on next password change
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network security: Do not store LAN Manager hash value on next password change' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object NoLMHash
  $traitement = $traitement.NoLMHash
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: LAN Manager authentication level
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network security: LAN Manager authentication level' is set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LmCompatibilityLevel
  $traitement = $traitement.LmCompatibilityLevel
  if($traitement -eq $null){
  $traitement  = "6"
  }
}
$data = @("Send LM & NTLM responses","Send LM & NTLM - use NTLMv2 session security if negotiated",
"Send NTLM responses only","Send NTLMv2 responses only",
"Send NTLMv2 responses only. Refuse LM","Send NTLMv2 responses only. Refuse LM & NTLM",
"Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "5")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: LDAP client signing requirements
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Network security: LDAP client signing requirements' is set to 'Negotiate signing' or higher"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LDAPClientIntegrity
  $traitement = $traitement.LDAPClientIntegrity
  if($traitement -eq $null){
  $traitement  = "3"
  }
}
$data = @("None","Negotiate signing","Require signature","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (([int]$traitement  -eq 1)-or([int]$traitement  -eq 2)) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: Minimum session security for NTLM SSP based (including secure RPC) clients
$ComplianceIndex += 1
$traitement = $null
$ComplianceName = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) clients' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object NTLMMinClientSec
  $traitement = $traitement.NTLMMinClientSec
  if($traitement -eq $null){
	  $traitement  = "Not Defined"
  }
}else{
	$traitement  = "Not Defined"
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -eq 537395200))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Network security: Minimum session security for NTLM SSP based (including secure RPC) servers
$ComplianceIndex += 1
$traitement = $null
$ComplianceName = "Ensure 'Network security: Minimum session security for NTLM SSP based (including secure RPC) servers' is set to 'Require NTLMv2 session security, Require 128-bit encryption'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object NTLMMinServerSec
  $traitement = $traitement.NTLMMinServerSec
  if($traitement -eq $null){
	  $traitement  = "Not Defined"
  }
}else{
	$traitement  = "Not Defined"
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -eq 537395200))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check System cryptography: Force strong key protection for user keys stored on the computer
$ComplianceIndex += 1
$traitement = $null
$ComplianceName = "Ensure 'System cryptography: Force strong key protection for user keys stored on the computer' is set to 'User is prompted when the key is first used' or higher "
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\Cryptography"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ForceKeyProtection
  $traitement = $traitement.ForceKeyProtection
  if($traitement -eq $null){
  $traitement  = "3"
  }
}
$data = @("User input is not required when new keys are stored and used","User is prompted when the key is first used",
			"User must enter a password each time they use a key","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (([int]$traitement  -eq 1)-or([int]$traitement  -eq 2))  
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check System objects: Require case insensitivity for non Windows subsystems
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'System objects: Require case insensitivity for non-Windows subsystems' is set to 'Enabled'"
$path =  "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ObCaseInsensitive
  $traitement = $traitement.ObCaseInsensitive
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)' is set to 'Enabled'"
$path =  "HKLM:SYSTEM\CurrentControlSet\Control\Session Manager"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ProtectionMode
  $traitement = $traitement.ProtectionMode
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Admin Approval Mode for the Built-in Administrator account
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Admin Approval Mode for the Built-in Administrator account' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object FilterAdministratorToken
  $traitement = $traitement.FilterAdministratorToken
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode' is set to 'Prompt for consent on the secure desktop'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ConsentPromptBehaviorAdmin
  $traitement = $traitement.ConsentPromptBehaviorAdmin
  if($traitement -eq $null){
  $traitement  = "6"
  }
}
$data = @("Elevate without prompting","Prompt for credentials on the secure desktop",
			"Prompt for consent on the secure desktop","Prompt for credentials","Prompt for consent",
			"Prompt for consent for non-Windows binaries","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "2")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Behavior of the elevation prompt for standard users
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Behavior of the elevation prompt for standard users' is set to 'Automatically deny elevation requests'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object ConsentPromptBehaviorUser
  $traitement = $traitement.ConsentPromptBehaviorUser
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Automatically deny elevation requests","Prompt for credentials on the secure desktop",
			"Not Defined","Prompt for credentials")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "0")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Detect application installations and prompt for elevation
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Detect application installations and prompt for elevation' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableInstallerDetection
  $traitement = $traitement.EnableInstallerDetection
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Only elevate UIAccess applications that are installed in secure locations
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Only elevate UIAccess applications that are installed in secure locations' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableSecureUIAPaths
  $traitement = $traitement.EnableSecureUIAPaths
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Run all administrators in Admin Approval Mode
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Run all administrators in Admin Approval Mode' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableLUA
  $traitement = $traitement.EnableLUA
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Switch to the secure desktop when prompting for elevation
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Switch to the secure desktop when prompting for elevation' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object PromptOnSecureDesktop
  $traitement = $traitement.PromptOnSecureDesktop
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Account Control: Virtualize file and registry write failures to per-user locations
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableVirtualization
  $traitement = $traitement.EnableVirtualization
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot








#Check User Account Control: Virtualize file and registry write failures to per-user locations
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'User Account Control: Virtualize file and registry write failures to per-user locations' is set to 'Enabled'"
$path =  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableVirtualization
  $traitement = $traitement.EnableVirtualization
  if($traitement -eq $null){
  $traitement  = "2"
  }
}
$data = @("Disabled","Enabled","Not Defined")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot







#Check Windows Firewall
Write-Host "`n [+] Begin Windows Firewall Audit`n" -ForegroundColor DarkGreen
Start-Sleep -s 1

#Check User Windows Firewall: Domain: Firewall state
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Firewall state' is set to 'On (recommended)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableFirewall
  $traitement = $traitement.EnableFirewall
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Off","On (recommended)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Domain: Inbound connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Inbound connections' is set to 'Block (default)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DefaultInboundAction
  $traitement = $traitement.DefaultInboundAction
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Allow","Block (default)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Domain: Outbound connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Outbound connections' is set to 'Allow (default)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DefaultOutboundAction
  $traitement = $traitement.DefaultOutboundAction
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Allow (default)","Block","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Domain: Settings: Display a notification
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Settings: Display a notification' is set to 'No'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DisableNotifications
  $traitement = $traitement.DisableNotifications
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Yes","No","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Domain: Logging: Name
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\domainfw.log'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFilePath
  $traitement = $traitement.LogFilePath
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -match 'System32\\domainfw.log')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Domain: Logging: Size limit (KB)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFileSize
  $traitement = $traitement.LogFileSize
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -ge '16384')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Domain: Logging: Log dropped packets
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Logging: Log dropped packets' is set to 'Yes'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogDroppedPackets
  $traitement = $traitement.LogDroppedPackets
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No (default)","Yes","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Domain: Logging: Log successful connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Domain: Logging: Log successful connections' is set to 'Yes'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogSuccessfulConnections
  $traitement = $traitement.LogSuccessfulConnections
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No (default)","Yes","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Private: Firewall state
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Firewall state' is set to 'On (recommended)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableFirewall
  $traitement = $traitement.EnableFirewall
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Off","On (recommended)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Private: Inbound connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Inbound connections' is set to 'Block (default)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DefaultInboundAction
  $traitement = $traitement.DefaultInboundAction
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Allow","Block (default)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Private: Outbound connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Outbound connections' is set to 'Allow (default)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DefaultOutboundAction
  $traitement = $traitement.DefaultOutboundAction
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Allow (default)","Block","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Private: Settings: Display a notification
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Settings: Display a notification' is set to 'No'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DisableNotifications
  $traitement = $traitement.DisableNotifications
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Yes","No","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Private: Logging: Name
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\privatefw.log'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFilePath
  $traitement = $traitement.LogFilePath
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -match 'System32\\privatefw.log')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Private: Logging: Size limit (KB)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFileSize
  $traitement = $traitement.LogFileSize
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -ge '16384')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Private: Logging: Log dropped packets
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Logging: Log dropped packets' is set to 'Yes'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogDroppedPackets
  $traitement = $traitement.LogDroppedPackets
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No (default)","Yes","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Private: Logging: Log successful connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Private: Logging: Log successful connections' is set to 'Yes'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogSuccessfulConnections
  $traitement = $traitement.LogSuccessfulConnections
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No (default)","Yes","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Firewall state
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Firewall state' is set to 'On (recommended)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object EnableFirewall
  $traitement = $traitement.EnableFirewall
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Off","On (recommended)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Inbound connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Inbound connections' is set to 'Block (default)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DefaultInboundAction
  $traitement = $traitement.DefaultInboundAction
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Allow","Block (default)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot


#Check User Windows Firewall: Public: Outbound connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Outbound connections' is set to 'Allow (default)'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DefaultOutboundAction
  $traitement = $traitement.DefaultOutboundAction
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Allow (default)","Block","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Settings: Display a notification
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Settings: Display a notification' is set to 'No'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object DisableNotifications
  $traitement = $traitement.DisableNotifications
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("Yes","No","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Settings: Apply local firewall rules
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Settings: Apply local firewall rules' is set to 'No'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AllowLocalPolicyMerge
  $traitement = $traitement.AllowLocalPolicyMerge
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No","Yes (default)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Settings: : Apply local connection security rules
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Settings: : Apply local connection security rules' is set to 'No'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object AllowLocalIPsecPolicyMerge
  $traitement = $traitement.AllowLocalIPsecPolicyMerge
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No","Yes (default)","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Logging: Name
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFilePath
  $traitement = $traitement.LogFilePath
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -match 'System32\\publicfw.log')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check User Windows Firewall: Public: Logging: Name
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Logging: Name' is set to '%SystemRoot%\System32\logfiles\firewall\publicfw.log'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFilePath
  $traitement = $traitement.LogFilePath
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (($traitement  -match 'System32\\publicfw.log')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Public: Logging: Size limit (KB)
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Logging: Size limit (KB)' is set to '16,384 KB or greater'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogFileSize
  $traitement = $traitement.LogFileSize
  if($traitement -eq $null){
  $traitement  = ""
  }
}else{
	$traitement  = ""
}
$CurrentValue	= $traitement
$ComplianceOrNot	= (([int]$traitement  -ge '16384')) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Public: Logging: Log dropped packets
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Logging: Log dropped packets' is set to 'Yes'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogDroppedPackets
  $traitement = $traitement.LogDroppedPackets
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No (default)","Yes","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot

#Check Windows Firewall: Public: Logging: Log successful connections
$ComplianceIndex += 1 
$traitement = $null
$ComplianceName = "Ensure 'Windows Firewall: Public: Logging: Log successful connections' is set to 'Yes'"
$path =  "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile\Logging"
$exist = Test-Path $path
if ( $exist -eq $true) {
  $traitement = Get-ItemProperty $path |Select-Object LogSuccessfulConnections
  $traitement = $traitement.LogSuccessfulConnections
  if($traitement -eq $null){
  $traitement  = "2"
  }
}else{
	$traitement  = "2"
}
$data = @("No (default)","Yes","Not configured")
$CurrentValue	= $data[[int]$traitement]
$ComplianceOrNot	= (($traitement  -match "1")) 
$ComplianceHTML += ContentHTML $ComplianceIndex $ComplianceName $CurrentValue $ComplianceOrNot
$ComplianceHTML = "$ComplianceHTML </tbody></table>"
$ComplianceHTML = "$ComplianceHTMLHead $ComplianceHTML"
$footer = @"
<script>
var acc = document.getElementsByClassName('accordion');
var i;

for (i = 0; i < acc.length; i++) {
  acc[i].addEventListener('click', function() {
    this.classList.toggle('active');
    var panel = this.nextElementSibling;
    if (panel.style.display === 'block') {
      panel.style.display = 'none';
	  this.children[0].innerHTML = ' [ show ]';
    } else {
      panel.style.display = 'block';
	  this.children[0].innerHTML = ' [ hide ]';
    }
  });
}
</script>
"@
$Report = ConvertTo-HTML -Body "$ToolDetails $ComputerName $OSinfo $ProcessInfo $BiosInfo $DiscInfo $NetworkAdapterInfo $LocalShareInfo  $Printers $ServicesInfo $LocalAccountInfo $ComplianceHTML $footer" -Head $header -Title "SECURITY AUDIT SERVICES, CDAC" -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>"
$htmlReportFileName = "./CDAC_AUDIT" + "-" + "$OSName" + ".html"
$Report | Out-File $htmlReportFileName

Set-Location "\"

Write-Host "`n`nAudit Completed at $(Get-Date) `n" -ForegroundColor DarkYellow

Read-Host -Prompt "Press Enter to exit"

