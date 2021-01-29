# Hybrid Azure AD Join Devices Health Checker
HybridDevicesHealthChecker PowerShell script checks the health status of hybrid Azure AD joined devices. This PowerShell script performs various tests on selected devices and shows the result on the Shell screen, grid view and generates HTML report.

#### Why is this script useful?
  - To check the hybrid status of specific device.
  - To check the hybrid status of a set of devices from TXT/CSV/XLS file.
  - To check the hybrid status of devices that are located in specific OU/Container.
  - To check the hybrid status of all devices in entire domain.
  - To automate a schedule task that checks the hybrid status of a set of devices.
  - To trace the changes (connection and disconnection) on hybrid devices.
  - To generate a friendly HTML report with the hybrid status.
  - To show the result on Grid View, so you can easily search in the result.


#### What does this script do?
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
 
User experience:

- Checking specific device: 

![Hybrid](https://github.com/mzmaili/HybridDevicesHealthChecker/blob/master/hybrid.PNG)

- Checking set of devices: 
![Check Devices](https://github.com/mzmaili/HybridDevicesHealthChecker/blob/master/Capture.PNG)

- The output report: 
![HTMLReport](https://github.com/mzmaili/HybridDevicesHealthChecker/blob/master/HTMLReport.PNG)

```azurepowershell
.SYNOPSIS 
    HybridDevicesHealthCheck PowerShell script. 
 
.DESCRIPTION 
    HybridDevicesHealthCheck.ps1 is a PowerShell script that checks the status of hybrid Azure AD joined devices. 
 
 
.PARAMETER 
    Device 
    Allows you to check specific device. 
 
.PARAMETER 
    DeviceList 
    Allows you to specify devices list from CSV/TXT/XLS file. 
    Note: make sure that the file contacis column wiht the name of "DeviceName" that includes the device name. 
 
.PARAMETER 
    OU 
    Allows you to check devices in specific OU or container. 
    Note: you can check all devices by following OU parameter with "all". 
 
.PARAMETER 
    OnScreenReport 
    Displays The health check result on PowerShell screen. 
 
.PARAMETER 
    HTMLReport 
    Generates HTML report and saves the health check result into it. 
 
.PARAMETER 
    SavedCreds 
    Uses the saved credentials option to connect to MSOnline, you can use any normal CLOUD only user who is having read permission on Azure AD devices. 
    Notes: - This parameter is very helpful when automating/running the script in task schduler. 
           - Update the saved credentials under the section "Update Saved credentials". 
 
.EXAMPLE 
    .\HybridDevicesHealthCheck -Device <Device Name> 
    Checks hybrid status for a single device, and shows the result on the shell window. 
 
.EXAMPLE 
    .\HybridDevicesHealthCheck -DeviceList C:\Devices.csv -OnScreenReport 
    Checks all devices in the selected file, and shows the result on the shell window and on grid view. 
 
.EXAMPLE 
    .\HybridDevicesHealthCheck -OU <OU/Container Name> 
    Checks all devices inside the OU/Container, and shows the result on shell window. 
 
.EXAMPLE 
    .\HybridDevicesHealthCheck -OU all -SavedCreds -HTMLReport 
    Checks all devices in the domain, uses the saved credentials to access MSOnline, and generates HTML report with the result. 
    Note: You can automate running this script using task scheduler. 
 
 
Output for a single device: 
----------- 
Device Name            : HYBRID 
Device ID              : xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx 
Approximate Last Logon : 5/13/2019 10:20:45 AM 
Hybrid Status          : Healthy 
Notes                  : The hybrid status of the device is healthy 
Recommended Action     : None 
 
 
====================================== 
|Hybrid Devices Health Check Summary:| 
====================================== 
Number of checked devices: 1 
Number of Healthly devices: 1 
Number of Unhealthly devices: 0
```
