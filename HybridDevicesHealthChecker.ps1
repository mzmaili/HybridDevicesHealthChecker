<# 
 
.SYNOPSIS
    HybridDevicesHealthCheckerer PowerShell script.

.DESCRIPTION
    HybridDevicesHealthCheckerer.ps1 is a PowerShell script that checks the status of hybrid Azure AD joined devices.

.AUTHOR:
    Mohammad Zmaili

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
    .\HybridDevicesHealthChecker -Device <Device Name>
    Checks hybrid status for a single device, and shows the result on the shell window.

.EXAMPLE
    .\HybridDevicesHealthChecker -DeviceList C:\Devices.csv -OnScreenReport
    Checks all devices in the selected file, and shows the result on the shell window and on grid view.

.EXAMPLE
    .\HybridDevicesHealthChecker -OU <OU/Container Name>
    Checks all devices inside the OU/Container, and shows the result on shell window.

.EXAMPLE
    .\HybridDevicesHealthChecker -OU all -SavedCreds -HTMLReport
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


========================================
|Hybrid Devices Health Check Summary:|
========================================
Number of checked devices: 1
Number of Healthly devices: 1
Number of Unhealthly devices: 0
#>


[cmdletbinding()]
param(
        [Parameter( Mandatory=$false)]
        [string]$Device,

        [Parameter( Mandatory=$false)]
        [string]$DeviceList,

        [Parameter( Mandatory=$false)]
        [string]$OU,

        [Parameter( Mandatory=$false)]
        [switch]$HTMLReport,
        
        [Parameter( Mandatory=$false)]
        [switch]$OnScreenReport,

        [Parameter( Mandatory=$false)]
        [switch]$SavedCreds

      )


#=========================
# Update Saved credentials
#=========================
$UserName = "user@domain.com"
$UserPass="PWD"
$UserPass=$UserPass|ConvertTo-SecureString -AsPlainText -Force
$UserCreds = New-Object System.Management.Automation.PsCredential($userName,$UserPass)


Function CheckInternet
{
$statuscode = (Invoke-WebRequest -Uri https://adminwebservice.microsoftonline.com/ProvisioningService.svc).statuscode
if ($statuscode -ne 200){
''
''
Write-Host "Operation aborted. Unable to connect to Azure AD, please check your internet connection." -ForegroundColor red -BackgroundColor Black
exit
}
}

Function CheckMSOnline{
''
Write-Host "Checking MSOnline Module..." -ForegroundColor Yellow
                            
    if (Get-Module -ListAvailable -Name MSOnline) {
        Import-Module MSOnline
        Write-Host "MSOnline Module has imported." -ForegroundColor Green -BackgroundColor Black
        ''
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        
        if ($SavedCreds){
            Connect-MsolService -Credential $UserCreds -ErrorAction SilentlyContinue
        }else{
            Connect-MsolService -ErrorAction SilentlyContinue
        }

        if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
            Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions." -ForegroundColor red -BackgroundColor Black
            exit
        }
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green -BackgroundColor Black
        ''
    } else {
        Write-Host "MSOnline Module is not installed." -ForegroundColor Red -BackgroundColor Black
        Write-Host "Installing MSOnline Module....." -ForegroundColor Yellow
        CheckInternet
        Install-Module MSOnline 
                                
        if (Get-Module -ListAvailable -Name MSOnline) {                                
        Write-Host "MSOnline Module has installed." -ForegroundColor Green -BackgroundColor Black
        Import-Module MSOnline
        Write-Host "MSOnline Module has imported." -ForegroundColor Green -BackgroundColor Black
        ''
        Write-Host "Connecting to MSOnline..." -ForegroundColor Yellow
        Connect-MsolService -ErrorAction SilentlyContinue
        
        if (-not (Get-MsolCompanyInformation -ErrorAction SilentlyContinue)){
            Write-Host "Operation aborted. Unable to connect to MSOnline, please check you entered a correct credentials and you have the needed permissions." -ForegroundColor red -BackgroundColor Black
            exit
        }
        Write-Host "Connected to MSOnline successfully." -ForegroundColor Green -BackgroundColor Black
        ''
        } else {
        ''
        ''
        Write-Host "Operation aborted. MsOnline was not installed." -ForegroundColor red -BackgroundColor Black
        exit
        }
    }



}

Function CheckCert ([String] $DeviceID, [String] $DeviceThumbprint){

    #Search for the certificate:
    if ($localCert = dir Cert:\LocalMachine\My\ | where { $_.Issuer -match "CN=MS-Organization-Access" -and $_.Subject -match "CN="+$DeviceID}){
    #The certificate exists
    #Cheching the certificate configuration

        $CertSubject = $localCert.subject
        $CertDNSNameList = $localCert.DnsNameList
        $CertThumbprint = $localCert.Thumbprint
        $NotBefore = $localCert.NotBefore
        $NotAfter = $localCert.NotAfter
        $IssuerName = $localCert.IssuerName
        $Issuer = $localCert.Issuer
        $subbectName = $localCert.SubjectName
        $Algorithm = $localCert.SignatureAlgorithm
        $PublicKey = $localCert.PublicKey
        $HasPrivateKey = $localCert.HasPrivateKey



        # Check Cert Expiration
        if (($NotAfter.toString("yyyy-M-dd")) -gt (Get-Date -format yyyy-M-dd)){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = $DeviceNotes + "`n" + "The certificate has expired."
            $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
        }


        # Check DeviceID and CertSubject
        $CertDNSName = $CertDNSNameList | select Punycode,Unicode

        if (($DeviceID -ne $CertDNSName.Punycode) -or ($DeviceID -ne $CertDNSName.Unicode)){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = $DeviceNotes + "`n" + "The certificate is not configured correctly."
            $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
        }



        # Check IssuerName
        if (($IssuerName.Name -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97") -or ($Issuer -ne "DC=net + DC=windows + CN=MS-Organization-Access + OU=82dbaca4-3e81-46ca-9c73-0950c1eaca97")){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = $DeviceNotes + "`n" + "Certificate Issuer is not configured correctly."
            $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
        }


        # Check AlgorithmFriendlyName
        if ($Algorithm.FriendlyName -ne "sha256RSA"){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = $DeviceNotes + "`n" + "Certificate Algorithm is not configured correctly."
            $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
        }

        # Check AlgorithmFValue
        if ($Algorithm.Value -ne "1.2.840.113549.1.1.11"){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = $DeviceNotes + "`n" + "Certificate Algorithm Value is not configured correctly."
            $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
        }
        

        # Check PrivateKey
        if ($HasPrivateKey -ne "True"){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = $DeviceNotes + "`n" + "Certificate PrivateKey does not exist."
            $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
        }



    
    }else{
    #Certificate does not exist.
    $DeviceStatus = "Not Healthy"
    $DeviceNotes = $DeviceNotes + "`n" + "The Device certificate does not exist."
    $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
    }
    

}#End of function

Function CheckDevice ([String] $DeviceName){

    $DeviceStatus ="Healthy"
    $DeviceNotes = "The hybrid status of the device is healthy"
    $DeviceRec = "None"


    #Test device connection:
    if (Test-Connection $DeviceName -count 1 -Quiet){

    # Test WINRM with Kerberos:
    if (Test-WSMan -ComputerName $DeviceName -Authentication Kerberos -ErrorAction SilentlyContinue) {
        #WSMan test successded:
        #Check OS version:
        $OSVersoin = Invoke-Command -ComputerName $DeviceName -ScriptBlock {([environment]::OSVersion.Version).major}
        if ($OSVersoin -ge 10){

        #The device is accessable.
        $DSReg = Invoke-Command -ComputerName $DeviceName -ScriptBlock {dsregcmd /status}


        $DJ = $DSReg | Select-String DomainJoin
        $DJ = ($DJ.tostring() -split ":")[1].trim()
        if ($DJ -ne "YES"){
            $DeviceStatus = "Not Healthy"
            $DeviceNotes = "The device is not joined to the local domain."
            $DeviceRec = "You need to join the device to the local domain in order to perform hybrid Azure AD join."

        }else{
            #The device is joined to the local domain.
    
            #Checking if the device connected to AzureAD
            $AADJ = $DSReg | Select-String AzureAdJoined
            $AADJ = ($AADJ.tostring() -split ":")[1].trim()
            if ($AADJ -ne "YES"){
            #The device is not connected to AAD:
                $DeviceStatus = "Not Healthy"
                $DeviceNotes = "The device is not connected to Azure AD."
                $DeviceRec = "Run 'dsregcmd /join' command to perform hybrid Azure AD join procedure and rerun the script, if the issue still persestant, check the possible courses on the article: http://www.microsoft.com/aadjerrors"

            }else{
                #The device is hybrid Azure AD join
        

                #Checking the KeyProvider:
                $KeyProvider = $DSReg | Select-String KeyProvider
                $KeyProvider = ($KeyProvider.tostring() -split ":")[1].trim()
                if (($KeyProvider -ne "Microsoft Platform Crypto Provider") -and ($KeyProvider -ne "Microsoft Software Key Storage Provider")){
                    $DeviceStatus = "Not Healthy"
                    $DeviceNotes = "The KeyProvider is not configured correctly."
                    $DeviceRec = "Run 'dsregcmd /join' command or restart the machine to perform hybrid Azure AD join procedure again."
                }

                # Check other values.

                #Checking the certificate:
                $DID = $DSReg | Select-String DeviceId
                $DID = ($DID.ToString() -split ":")[1].Trim()
        

                $DTP = $DSReg | Select-String Thumbprint
                $DTP = ($DTP.ToString() -split ":")[1].Trim()
        

                CheckCert -DeviceID $DID -DeviceThumbprint $DTP



        #Check the device status on AAD:
        $AADDevice = Get-MsolDevice -DeviceId $DID
        
        #Check if the device exist:
        if ($AADDevice.count -ge 1){
            #The device existing in AAD:
            #Check if the device is enabled:
            if ($AADDevice.Enabled -eq $false){
                $DeviceStatus = "Not Healthy"
                $DeviceNotes = "The device is not enabled in your Azure AD tenant."
                $DeviceRec = "Enable the device on Azure AD tenant. For more information, visit the link: https://docs.microsoft.com/en-us/azure/active-directory/devices/device-management-azure-portal#enable--disable-an-azure-ad-device"
            }

                #get ApproximateLastLogonTimestamp value
                $global:LastLogonTimestamp = $AADDevice.ApproximateLastLogonTimestamp
                

        }else{
        #Device does not exist:
        $DeviceStatus = "Not Healthy"
        $DeviceNotes = "The device does not exist in your Azure AD tenant."
        $DeviceRec = "Run 'dsregcmd /join' command to perform hybrid Azure AD join procedure and rerun the script, if the issue still persestant, check the possible courses on the article: http://www.microsoft.com/aadjerrors"

        }

#
            }

        }

        }else{
        # dsregcmd will not work.
        $DeviceStatus = "Not Healthy"
        $DeviceNotes = "The device has a Windows down-level OS version."
        $DeviceRec = "'dsregcmd /status' command can be run only on Windows 10, Windows Server 2016 and above verions." 
         
    }

    }else{
        #WSMAN test failed
        $DeviceStatus = "Not Healthy"
        $DeviceNotes ="Windows Remote Management is not configured corretly."
        $DeviceRec = "Make sure that the remote machine is joined to the local AD and make sure that WSMan configured to accespt the Kerberos authentication for remote execution. For more information, visit the link: https://docs.microsoft.com/en-us/windows/desktop/winrm/installation-and-configuration-for-windows-remote-management"
    }






    }else{
        #The device is not available
        $DID = ""
        $DeviceStatus = "Not Healthy"
        $DeviceNotes = "The device is not reachable."
        $DeviceRec = "Either the device name is incorrect or the device is not accessible."
    }



            $repobj = New-Object PSObject
            $repobj | Add-Member NoteProperty -Name "Device Name" -Value $DeviceName
            $repobj | Add-Member NoteProperty -Name "Device ID" -Value $DID
            $repobj | Add-Member NoteProperty -Name "Approximate Last Logon" -Value $global:LastLogonTimestamp
            $repobj | Add-Member NoteProperty -Name "Hybrid Status" -Value $DeviceStatus
            $repobj | Add-Member NoteProperty -Name "Notes" -Value $DeviceNotes
            $repobj | Add-Member NoteProperty -Name "Recommended Action" -Value $DeviceRec
            $repobj

            if ($OnScreenReport){
            $global:rep += $repobj
            }

            if ($HTMLReport){

            if ($DeviceStatus -eq "Healthy"){
                $bgcolor = "#00FF00"
                }else{
                $bgcolor = "#FF0000"
            }

            $global:htmlTable += "<p>
                                 <tr>
                                 <td>"+ $DeviceName +"</td>
                                 <td>" + $DID +"</td>
                                 <td>" + $global:LastLogonTimestamp +"</td>
                                 <td bgcolor=" + $bgcolor + ">"+ $DeviceStatus + "</td>
                                 <td>"+ $DeviceNotes +"</td>
                                 <td>"+ $DeviceRec +"</td>
                                 </tr>"
            }

            if ($DeviceStatus -eq "Healthy"){
                $global:Hnum+=1
                $global:allnum+=1
            }else{
                $global:Uhnum+=1
                $global:allnum+=1
            }

            $DeviceName=""
            $DID=""
            $global:LastLogonTimestamp=""
            $DeviceStatus=""
            $DeviceNotes=""
            $DeviceRec = ""



}#end of checkDevice function


$global:rep =@()
$global:Hnum=0
$global:Uhnum=0
$global:allnum=0


$global:htmlTable = "<br>
                    <p>
                    <table>
                    <tr>
                    <th width='7%'>Device Name</th>
                    <th width='15%'>Device ID</th>
                    <th width='14%'>Approximate Last Logon</th>
                    <th width='5%'>Hybrid Status</th>
                    <th>Notes</th>
                    <th>Recommended Action</th>
                    </tr>"

cls

'==================================================='
Write-Host '          Hybrid Devices Health Checker          ' -ForegroundColor Green 
'==================================================='


CheckMSOnline

if ($Device){
    # Device param selsected.
    Write-Host "Checking Device" $Device "..." -ForegroundColor Yellow
    CheckDevice -DeviceName $Device

}elseif ($DeviceList.length -ne 0){
    #There is file input
    #Check the file location
    $CSVFile = $DeviceList
    if (-not (Test-Path $CSVFile)) {
        #The file does not exist.
        Write-Host "File not exist"
    }else{
        $data = import-Csv $CSVFile
        ForEach ($d in $data){
            $DeviceName = $d.DeviceName
            Write-Host "Checking Device" $d.DeviceName "..." -ForegroundColor Yellow
            CheckDevice -DeviceName $d.DeviceName
        }
    }


}elseif ($OU.length -ne 0){
        #There is OU input


        Write-Host "Checking Active Directory Module..." -ForegroundColor Yellow
        if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Import-Module ActiveDirectory
            Write-Host "Active Directory Module has imported." -ForegroundColor Green -BackgroundColor Black
        } else {
            Write-Host "Active Directory Module is not installed." -ForegroundColor red -BackgroundColor Black
    
            Write-Host "Installing Active Directory Module..." -ForegroundColor Yellow
            Add-WindowsFeature RSAT-AD-PowerShell
            ''
            if (Get-Module -ListAvailable -Name ActiveDirectory) {
            Write-Host "Active Directory Module has installed." -ForegroundColor Green -BackgroundColor Black
            Import-Module ActiveDirectory
            Write-Host "Active Directory Module has imported." -ForegroundColor Green -BackgroundColor Black
            } else {
            #######
            Write-Host "Operation aborted. Active Directory Module was not installed." -ForegroundColor red -BackgroundColor Black
            exit
            }
        }



        if ($OU -eq "all" -or $OU -eq "All" -or $OU -eq "ALL"){
            #All Domain machines needed to be tested:    
            $data = (Get-ADComputer -Filter *).name

            if ($data.count -gt 0 ){
            $num=1
                ForEach ($d in $data){
                    $DeviceName = $d.DeviceName
                    ''
                    #Write-Host "Checkig Device '$DeviceName' ..." -ForegroundColor Yellow
                    Write-Host "Checking Device" $num "of" $data.count "..." -ForegroundColor Yellow
                    CheckDevice -DeviceName $d
                    $num+=1
                }
            }else{
                Write-Host "There is no computers has been retreived."
                ###exit
            }
            

            }else{
                #Check the OU    
                $OUDN = (Get-ADObject -Filter "(ObjectClass -eq 'organizationalUnit' -or ObjectClass -eq 'container') -and (name -eq '$OU')").DistinguishedName

                if ($OUDN.length -ne 0){
                $data = (Get-ADComputer -Filter * -SearchBase $OUDN).name
                if ($data.count -gt 0 ){
                $num=1
                    ForEach ($d in $data){
                        $DeviceName = $d.DeviceName
                        ''
                        Write-Host "Checking Device" $num "of" $data.count "..." -ForegroundColor Yellow
                        CheckDevice -DeviceName $d
                        $num+=1
                    }
                }else{
                    ''
                    Write-Host "The entered OU/Container does not include any computer account." -ForegroundColor red -BackgroundColor Black
                }

            }else{
            ''
            Write-Host "The entered OU/Container does not exist." -ForegroundColor red -BackgroundColor Black
            }

        }
}


Function HTMLReport{
$reptime = Get-Date

$RepReport="<html>
           <style>
           BODY{font-family: Arial; font-size: 8pt;}
           H1{font-size: 16px;}
           H2{font-size: 14px;}
           H3{font-size: 12px;}
           TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
           TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
           TD{border: 1px solid black; padding: 5px; }
           </style>
           <body>
           <br>
           <h1 align=""center"">Hybrid Devices Health Checker Report</h1>
           <h3 align=""center"">Generated On: $reptime</h3>"


$RepReport += "<h3>Hybrid Devices Health Check Summary</h3>
                      <p>Number of checked devices: $global:allnum</p>
                      <p>Number of Healthly devices: $global:Hnum</p>
                      <p>Number of Unhealthly devices: $global:Uhnum</p>
                      <p>
                      "


$global:htmlTable += "</table></p>"
            
            

$htmlrep = $RepReport + $global:htmlTable + "</body></html>"

$Date=("{0:s}" -f (get-date)).Split("T")[0] -replace "-", ""
$Time=("{0:s}" -f (get-date)).Split("T")[1] -replace ":", ""
$filerep = "HybridDevicesHealthCheckerReport_" + $Date + $Time + ".html"    
$htmlrep | Out-File $filerep -Encoding UTF8
$loc=Get-Location
''
Write-host $filerep "report has been created on the path:" $loc -ForegroundColor green -BackgroundColor Black


}


if ($HTMLReport) {
    HTMLReport
}

if ($OnScreenReport) {
    $rep | Out-GridView -Title "Hybrid Devices Health Check Report"
}



''
Write-Host "======================================"
Write-Host "|Hybrid Devices Health Check Summary:|"
Write-Host "======================================"
Write-Host "Number of checked devices:" $global:allnum
Write-Host "Number of Healthly devices:" $global:Hnum
Write-Host "Number of Unhealthly devices:" $global:Uhnum

