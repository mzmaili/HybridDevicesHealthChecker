# HybridDevicesHealthChecker
HybridDevicesHealthChecker PowerShell script checks the health status of hybrid Azure AD joined devices. This PowerShell script performs various tests on selected devices and shows the result on the Shell screen, grid view and generates HTML report.

Why is this script useful?
  - To check the hybrid status of specific device.
  - To check the hybrid status of a set of devices from TXT/CSV/XLS file.
  - To check the hybrid status of devices that are located in specific OU/Container.
  - To check the hybrid status of all devices in entire domain.
  - To automate a schedule task that checks the hybrid status of a set of devices.
  - To trace the changes (connection and disconnection) on hybrid devices.
  - To generate a friendly HTML report with the hybrid status.
  - To show the result on Grid View, so you can easily search in the result.

What does this script do?
  - Checks the join status to the local AD.
  - Checks the connection status to Azure AD.
  - Checks the device certificate configuration.
  - Checks the device existence in Azure AD.
  - Checks the device status in Azure AD.
  - Shows the health status of each device in various ways.
  - Provides recommendations to fix unhealthy devices.
 
 Also, the PowerShell script:
  - Checks if ‘MSOnline module is installed. If not, it installs and imports it.
  - Checks if ‘ActiveDirectory’ module is installed (when selecting OU parameter). If not, it installs and imports it.
 
