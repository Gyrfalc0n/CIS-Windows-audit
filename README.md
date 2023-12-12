# CIS Windows Audit

This repository contains a PowerShell script (`audit.ps1`) designed to perform a comprehensive audit of a Windows machine based on the Center for Internet Security (CIS) benchmarks. The script provides a menu-driven interface for easy navigation and execution of specific audit tasks.

## Usage

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/Gyrfalc0n/CIS-Windows-audit.git
    ```

2. Navigate to the repository:

```
cd CIS-Windows-audit
```

3. Execute the audit script:

```
.\audit.ps1
```

This will launch a menu with various options for auditing Windows settings.

## Menu Options

The menu provides the following options:

1. **Show general information about the machine**: Displays general information about the Windows machine.

2. **Show user information**: Provides details about users on the system.

3. **Show Windows Firewall information**: Displays information about the Windows Firewall configuration.

4. **Show minimization services**: Shows details about services running on the system.

5. **Audit the system according to CIS**: Performs a comprehensive audit based on the CIS benchmarks for Windows.

6. **Open results in Notepad**: Opens the audit results in Notepad for easy review.

7. **Quit**: Exits the script.

## Script Structure

The `audit.ps1` script is organized into functions for each audit task. The main function, `ShowMenu`, provides a user-friendly menu for selecting specific audit tasks. Each option in the menu corresponds to a function that performs a specific audit.

```powershell
function ShowMenu {
    # Menu options...
}

# Function definitions...

# Main script execution...
```

## Results
The audit results are stored in separate files within the results directory. The naming convention for result files is audit_results_<timestamp>.txt.

## Contributions
Contributions are welcome! If you find issues or have suggestions for improvements, feel free to open an issue or submit a pull request.

## License
This project is licensed under the GNU General Public License v3.0. See the [LICENSE](https://github.com/Gyrfalc0n/CIS-Windows-audit/blob/main/LICENSE) file for details.