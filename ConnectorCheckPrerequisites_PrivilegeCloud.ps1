###########################################################################
#
# NAME: Privilege Cloud Prerequisites check
#
# AUTHOR:  Mike Brook
#
# COMMENT: 
# Script checks prerequisites for Privilege Cloud Connector machine
#
#
###########################################################################

 <#
  .DESCRIPTION
  Script checks prerequisites for Privilege Cloud Connector machine
  
  .PARAMETER OutOfDomain
  .PARAMETER Troubleshooting
  .PARAMETER SkipVersionCheck
  .PARAMETER SkipIPCheck
 
  .EXAMPLE 
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1
  
  .EXAMPLE - Run checks if machine is out of domain
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -OutOfDomain

  .EXAMPLE - Troubleshoot certain components
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -Troubleshooting

  .EXAMPLE - Skip Online Checks
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -SkipVersionCheck -SkipIPCheck
  
#>
[CmdletBinding(DefaultParameterSetName="Regular")]
param(
	# Use this switch to Exclude the Domain user check
	[Parameter(ParameterSetName='Regular',Mandatory=$false)]
	[switch]$OutOfDomain,
	# Use this switch to troubleshoot specific items
	[Parameter(ParameterSetName='Troubleshoot',Mandatory=$false)]
	[switch]$Troubleshooting,
	# Use this switch to check CPM Install Connection Test
	[Parameter(ParameterSetName='CPMConnectionTest',Mandatory=$false)]
	[switch]$CPMConnectionTest,
    # Use this switch to skip online checks
    [Parameter(ParameterSetName='Regular',Mandatory=$false)]
    [switch]$SkipVersionCheck,
    [Parameter(ParameterSetName='Regular',Mandatory=$false)]
    [switch]$SkipIPCheck,
    [Parameter(ParameterSetName='Regular',Mandatory=$false)]
    [switch]$DisableNLA,
    [Parameter(ParameterSetName='Regular',Mandatory=$false)]
    [switch]$InstallRDS
)

# ------ SET Script Prerequisites ------
##############################################################

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

## Enforce TLS
$script:enforceTLS = $true

## List of checks to be excluded when machine is out of domain
$arrCheckPrerequisitesOutOfDomain = @("DomainUser","remoteAppDomainUserPermissions") #PSM

## List of checks to be performed on every run of the script
$arrCheckPrerequisitesGeneral = @(
#"VaultConnectivity", #General
"CustomerPortalConnectivity", #General
"CheckIdentityCustomURL",
"OSVersion", #General
"Processors", #General
"Memory", #General
"InterActiveLoginSmartCardIsDisabled", #General
"UsersLoggedOn", #General
#"IPV6", #General
"MachineNameCharLimit", #General
"MinimumDriveSpace", #General
"DotNet", #General
"CheckEndpointProtectionServices", #General
"PendingRestart" #General
)

$arrCheckPrerequisitesSecureTunnel = @(
"TunnelConnectivity", #SecureTunnel
"ConsoleNETConnectivity", #SecureTunnel
"ConsoleHTTPConnectivity", #SecureTunnel
"SecureTunnelLocalPort" #SecureTunnel
)


$arrCheckPrerequisitesPSM = @(
"VaultConnectivity", # PSM & CPM
"SQLServerPermissions", #PSM
"SecondaryLogon", #PSM
"KUsrInitDELL", #PSM
"GPO-Local", #PSM
"GPO-Domain", #PSM
"CheckNoProxy" #PSM
)

$arrCheckPrerequisitesCPM = @(
#"CRLConnectivity" #CPM
"VaultConnectivity" #PSM & CPM
)

$arrCheckPrerequisitesCM = @(
"ConnectorManagementScripts", #CM
"ConnectorManagementAssets", #CM
"ConnectorManagementComponentRegistry", #CM
"ConnectorManagementIOT", #CM
"ConnectorManagementIOTCert" # CM
)

$arrCheckPrerequisitesDPA = @(
"DPA-Assets", 
"DPA-BackendAccess",
"DPA-Portal",
"DPA-IOT",
"DPA-IOTCert"
)

## If not OutOfDomain then include domain related checks
If (-not $OutOfDomain){
	$arrCheckPrerequisitesPSM += $arrCheckPrerequisitesOutOfDomain
}

#all
$arrCheckPrerequisites = @{General = $arrCheckPrerequisitesGeneral},@{CPM = $arrCheckPrerequisitesCPM},@{PSM = $arrCheckPrerequisitesPSM},@{SecureTunnel = $arrCheckPrerequisitesSecureTunnel},@{ConnectorManagement = $arrCheckPrerequisitesCM},@{DPA = $arrCheckPrerequisitesDPA}

$componentMapping = @{
    "SIA - Secure Infrastructure Access (DPA)" = $arrCheckPrerequisitesDPA
    "CM - Connector Management" = $arrCheckPrerequisitesCM
    "PSM - Privilege Session Manager" = $arrCheckPrerequisitesPSM
    "CPM - Central Policy Manager" = $arrCheckPrerequisitesCPM
    "ST - Secure Tunnel (Legacy HTML5, SIEM)" = $arrCheckPrerequisitesSecureTunnel
}



## List of GPOs to check
$arrGPOPSM = @(
       [pscustomobject]@{Name='Require user authentication for remote connections by using Network Level Authentication';Expected='Not Configured'} # Break PSM func
	   [pscustomobject]@{Name='Select RDP transport protocols'; Expected='Not Configured'}	# Break PSM func
	   [pscustomobject]@{Name='Set client connection encryption level'; Expected='Not Configured'} # Break PSM func
       [pscustomobject]@{Name='Allow CredSSP authentication'; Expected='Not Configured'} # Break PSM func
       [pscustomobject]@{Name='Interactive logon: Require Smart card'; Expected='Not Configured'} # Break PSM func
   )
   
$arrGPOGeneric = @(
       [pscustomobject]@{Name='Allow remote server management through WinRM'; Expected='Not Configured'} # RDS install
       [pscustomobject]@{Name='Allow Remote Shell Access'; Expected='Not Configured'} # RDS install
   )


##############################################################

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:PSMConfigFile = "_ConnectorCheckPrerequisites_PrivilegeCloud.ini"

# Script Version
[int]$versionNumber = "36"

# ------ SET Files and Folders Paths ------
# Set Log file path
$global:LOG_DATE = $(get-date -format yyyyMMdd) + "-" + $(get-date -format HHmmss)
$global:LOG_FILE_PATH = "$ScriptLocation\_ConnectorCheckPrerequisites_PrivilegeCloud.log"
$global:CONFIG_PARAMETERS_FILE = "$ScriptLocation\$PSMConfigFile"

# ------ SET Global Parameters ------
$global:g_ConsoleIPstd = "console.privilegecloud.cyberark.com"
$global:g_ConsoleIPispss = "console.privilegecloud.cyberark.cloud"
$global:g_ScriptName = "ConnectorCheckPrerequisites_PrivilegeCloud.ps1"
$global:g_CryptoPath = "C:\ProgramData\Microsoft\Crypto"
$global:CollectionName="PSM-RemoteApp"

# ------ SET Schedule Task Parameters ------
$global:TriggerAtStart = New-ScheduledTaskTrigger -AtStartup
$global:TriggerAtLogon = New-ScheduledTaskTrigger -AtLogon
$global:ActionNLA = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy Unrestricted -File `"$ScriptLocation\$g_ScriptName`" `"-skipIPCheck`" `"-skipVersionCheck`" `"-DisableNLA`""
$global:ActionRDS = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -NoExit -ExecutionPolicy Unrestricted -File `"$ScriptLocation\$g_ScriptName`" `"-skipIPCheck`" `"-skipVersionCheck`" `"-InstallRDS`""
$global:ActionRDSoutOfDomain = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -NoExit -ExecutionPolicy Unrestricted -File `"$ScriptLocation\$g_ScriptName`" `"-skipIPCheck`" `"-skipVersionCheck`" `"-OutOfDomain`" `"-InstallRDS`""
$global:taskNameNLA = "DisableNLAafterRDSInstall"
$global:taskNameRDS = "CompleteRDSInstallAfterRestart"
$global:taskDescrNLA = "DisableNLAafterRDSInstall"
$global:taskDescrRDS = "CompleteRDSInstallAfterRestart"
$global:taskNameDisableNLA = "DisableNLAafterRDSInstall"
$global:taskNameDisableRDS = "CompleteRDSInstallAfterRestart"

$global:table = ""
$SEPARATE_LINE = "------------------------------------------------------------------------" 
$g_SKIP = "SKIP"

# Supported AWS Regions
$script:availableRegions = @(
    [pscustomobject]@{RegionName = "US East" ; RegionCode = "us-east-1" ; Description = "Virginia"} # Virginia
    [pscustomobject]@{RegionName = "Canada" ; RegionCode = "ca-central-1" ; Description = "Montreal"} # Montreal
    [pscustomobject]@{RegionName = "Frankfurt" ; RegionCode = "eu-central-1" ; Description = "Frankfurt"} # Frankfurt
    [pscustomobject]@{RegionName = "London" ; RegionCode = "eu-west-2" ; Description = "London"} # London
    [pscustomobject]@{RegionName = "Eu South" ; RegionCode = "eu-south-1" ; Description = "Milan" } # Milan
    [pscustomobject]@{RegionName = "AP Southeast" ; RegionCode = "ap-southeast-1" ; Description = "Singapore"} # Singapore
    [pscustomobject]@{RegionName = "Sydney" ; RegionCode = "ap-southeast-2" ; Description = "Sydney"} # Sydney
    [pscustomobject]@{RegionName = "Tokyo" ; RegionCode = "ap-northeast-1" ; Description = "Tokyo"} # Tokyo
    [pscustomobject]@{RegionName = "Asia Pacific" ; RegionCode = "ap-south-1" ; Description = "Australia Sydney ,India Mumbai"} # Mumbai
    [pscustomobject]@{RegionName = "ap-southeast-3" ; RegionCode = "ap-southeast-3" ; Description = "Indonesia Jakarta"}
    [pscustomobject]@{RegionName = "me-central-1" ; RegionCode = "me-central-1" ; Description = "UAE"} # UAE
    [pscustomobject]@{RegionName = "il-central-1" ; RegionCode = "il-central-1" ; Description = "Tel Aviv"} # Tel Aviv
)


#region Troubleshooting
Function Show-Menu{
    Clear-Host
    Write-Host "================ Troubleshooting Guide ================"
    
    Write-Host "1: Press '1' to Disable IPv6 (Legacy)" -ForegroundColor Green
    Write-Host "2: Press '2' to Enable SecondaryLogon Service" -ForegroundColor Green
    Write-Host "3: Press '3' to Run CPM Install Connection Test" -ForegroundColor Green
    Write-Host "4: Press '4' to Retry Install RDS" -ForegroundColor Green
    Write-Host "5: Press '5' to Verify InstallerUser status" -ForegroundColor Green
    Write-Host "Q: Press 'Q' to quit."
}
Function Troubleshooting{

Function DisableIPV6(){
    #Disable IPv6 on NIC
	Disable-NetAdapterBinding -Name "*" -ComponentID ms_tcpip6

	#Disable IPv6 on Registry
	New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisabledComponents" -Value "0xFFFFFFFF" -PropertyType DWORD -Force

    Write-LogMessage -Type Success -Msg "Disabled IPv6, Restart machine to take affect."
}

Function EnableSecondaryLogon(){

$GetSecondaryLogonService = Get-Service -Name seclogon
$GetSecondaryLogonServiceStatus = Get-Service -Name seclogon | select -ExpandProperty status
$GetSecondaryLogonServiceStartType = Get-Service -Name seclogon | select -ExpandProperty starttype

If (($GetSecondaryLogonServiceStartType -eq "Disabled") -or ($GetSecondaryLogonServiceStartType -eq "Manual")){
Get-Service seclogon | Set-Service -StartupType Automatic
}

$GetSecondaryLogonService | Start-Service
$GetSecondaryLogonService.WaitForStatus('Running','00:00:05')
$GetSecondaryLogonServiceStatus = Get-Service -Name seclogon | select -ExpandProperty status

if($GetSecondaryLogonServiceStatus -eq "Running"){
    Write-LogMessage -Type Success -Msg "Successfully started Secondary Logon Service!"
}
Else{
    Write-LogMessage -Type Warning -Msg "Something went wrong, do it manually :("
    }
}
Function CPMConnectionTestFromTroubleshooting(){
    $CPMConnectionTest = $true
    CPMConnectionTest
}


Function TestIdentityServiceAccount(){
	Write-LogMessage -type Info -MSG "Begin TestIdentityServiceAccount." -Early
	Write-Host "This check will perform a basic API authentication call and will return success or fail" -ForegroundColor Magenta
	pause
	
	#Fetch values from .ini file
	Write-LogMessage -type Info -MSG "Checking if we can fetch the portal URL from $CONFIG_PARAMETERS_FILE" -Early
	$parameters = Try{Import-CliXML -Path $CONFIG_PARAMETERS_FILE}catch{Write-LogMessage -type Info -MSG "$($_.exception.message)" -Early}
	
	if($parameters.PortalURL -eq $null){
		$PlatformTenantId = Read-Host "Please enter your portal URL (eg; 'https://testenv.cyberark.cloud')"
	}
	Else{
		$PlatformTenantId = $parameters.PortalURL
	}
	
	# grab the subdomain, depending how the user entered the url (hostname only or URL).
	if($PlatformTenantId -match "https://"){
		$PlatformTenantId = ([System.Uri]$PlatformTenantId).host
		$portalSubDomainURL = $PlatformTenantId.Split(".")[0]
	}
	Else{
		$portalSubDomainURL = $PlatformTenantId.Split(".")[0]
	}
	Try{

		$creds = Get-Credential -Message "Enter Privilege Cloud InstallerUser Credentials"
		if($($creds.username) -match ' ' -or $($creds.GetNetworkCredential().Password) -match ' '){
			Write-Host "Your Username/password has a space in it. We would fix it, but you may end up pasting it somewhere and wonder why it doesn't work :)" -ForegroundColor Yellow
			Write-Host "Remove it and try again." -ForegroundColor Yellow
			Pause
            Exit
		}
	
		#PlatformParams
		$BasePlatformURL = "https://$portalSubDomainURL.cyberark.cloud"
		Write-LogMessage -type Info -MSG "Portal URL set: $BasePlatformURL" -Early
		#Platform Identity API
		$IdentityHeaderURL = Get-IdentityURL -idURL $BasePlatformURL
        if($IdentityHeaderURL -like "*Error*"){
            Write-LogMessage -type Error -MSG "Error accessing URL '$($BasePlatformURL)' $($IdentityHeaderURL)"
            return
        }Else{
		    $IdaptiveBasePlatformURL = "https://$IdentityHeaderURL"
		    Write-LogMessage -type Info -MSG "Identity URL set: $IdaptiveBasePlatformURL" -Early
		    $IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
		    $startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
		    $startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
		    $LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"


		    #Begin Start Authentication Process
		    Write-LogMessage -type Info -MSG "Begin Start Authentication Process: $startPlatformAPIAuth" -Early
            $IdentityTenantId = $IdentityHeaderURL.Split(".")[0]
		    $startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $creds.UserName ; Version = "1.0"} | ConvertTo-Json -Compress
		    $IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 10
		    $IdaptiveResponse.Result.Challenges.mechanisms
		    
            if(-not($IdaptiveResponse.Result.Challenges.mechanisms -eq $null))
            {
		        #Begin Advanced Authentication Process
		        Write-LogMessage -type Info -MSG "Begin Advanced Authentication Process: $startPlatformAPIAdvancedAuth" -Early
		        $startPlatformAPIAdvancedAuthBody = @{SessionId = $($IdaptiveResponse.Result.SessionId); MechanismId = $($IdaptiveResponse.Result.Challenges.mechanisms.MechanismId); Action = "Answer"; Answer = $creds.GetNetworkCredential().Password } | ConvertTo-Json -Compress
		        $AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30
		        $AnswerToResponse.Result
            }
            Else
            {
                Write-Host "Did not receive challenge response, check response recieved below:" -ForegroundColor Red
                $IdaptiveResponse
                # Tenant has Custom URL enabled, we don't support it yet.
                if($IdaptiveResponse.Result.PodFqdn){
                    Write-LogMessage -type Warning -MSG "Hint: It looks like you have configured customized URL in Identity Administration, please disable it and try again (wait at least 10 min for changes to take affect)."
                    write-host "Hint: Navigate to Identity Administration -> Settings -> Customization -> Tenant URLs -> Delete the Custom URL and make sure default is '$($IdentityHeaderURL)'" -ForegroundColor Yellow
                }
            }
	
		    if($AnswerToResponse.Result.Summary -eq "LoginSuccess"){
		    	Write-Host "Final Identity Result: Success!" -ForegroundColor Green
		    	#LogOff
		    	Write-LogMessage -type Info -MSG "Begin Logoff Process" -Early
		    	$logoff = Invoke-RestMethod -Uri $LogoffPlatform -Method Post -Headers $IdentityHeaders
		    }Else{
		    	Write-Host "Final Identity Result: Failed!" -ForegroundColor Red
		    		if($IdaptiveResponse.Result.Challenges.mechanisms.AnswerType.Count -gt 1){
		    			Write-LogMessage -type Info -MSG "Challenge mechanisms greater than one:" -Early
		    			$IdaptiveResponse.Result.Challenges.mechanisms.AnswerType
		    			Write-LogMessage -type Warning -MSG "Hint: Looks like MFA is enabled, make sure it's disabled."
		    		}
		    	}
	        }
	}catch
	{
		Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri))"
        Write-Host "Final Identity Result: Failed!" -ForegroundColor Red
	}
		#### Check against PVWA Directly, sometimes the shadowuser can be suspended/disabled in the vault but will be fine in identity. ####

			Write-LogMessage -type Info -MSG "Also testing directly against Privilege Cloud API." -Early
			Start-Sleep 3
           $basePVWA = "https://$portalSubDomainURL.privilegecloud.cyberark.cloud"
			$pvwaLogoff = "$basePVWA/passwordvault/api/Auth/logoff"
			$basePVWALoginCyberArk = "$basePVWA/passwordvault/api/Auth/CyberArk/Logon"
			$pvwaLogonBody = @{ username = $creds.UserName; password = $creds.GetNetworkCredential().Password } | ConvertTo-Json -Compress
            $pvwaLogonToken = $null
		# Login to PVWA
		Try{
			Write-LogMessage -type Info -MSG "Begin Login: $basePVWALoginCyberArk" -Early
			$pvwaLogonToken = Invoke-RestMethod -Method Post -Uri $basePVWALoginCyberArk -Body $pvwaLogonBody -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable pvwaResp
            if($pvwaLogonToken){
                Write-Host "Final Privilege Cloud Result: Success!" -ForegroundColor Green
            }
            else
			{
				Write-Host "Final Privilege Cloud Result: Failed!" -ForegroundColor Red
                $pvwaResp
			}
		}Catch
		{
            Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $_.exception.message $($_.ErrorDetails.Message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri)) $pvwaResp"
            Write-Host "Final Privilege Cloud Result: Failed!" -ForegroundColor Red
			#Lets check if identity was ok, then if vault is not, we know the pw is correct but user is most likely suspended/disabled.
			if(($AnswerToResponse.Result.Summary -eq "LoginSuccess") -and ($pvwaResp -like "*Authentication failure*")){
				Write-Host "Final Privilege Cloud Result: Failed!" -ForegroundColor Red
				Write-Host "Hint: User is most likely Suspended/Disabled in the Vault" -ForegroundColor Yellow
				Write-Host "Hint: Perform `"Set Password`" and `"MFA Unlock`" from Identity Portal and try again." -ForegroundColor Yellow
			}
		}
        Finally{
            #logoff
			Write-LogMessage -type Info -MSG "Begin Logoff Process" -Early
			Try{$logoff = Invoke-RestMethod -Uri $pvwaLogoff -Method Post -Headers $pvwaLogonHeader}Catch{}
            $creds = $null
        }
	Write-LogMessage -type Info -MSG "Finish TestIdentityServiceAccount." -Early
	}

do
 {
     Show-Menu
     $selection = Read-Host "Please select an option"
     switch ($selection)
     {
         '1' {
              DisableIPV6
             }
         '2' {
              EnableSecondaryLogon
             }
         '3' {
              CPMConnectionTestFromTroubleshooting
             }
         '4' {
              InstallRDS
			  Pause
			  break
             }
         '5' {
             TestIdentityServiceAccount
             }
     }
     pause
 }
 until ($selection -eq 'q')
 exit
}
#endregion

#region Find Components
# @FUNCTION@ ======================================================================================================================
# Name...........: Get-ServiceInstallPath
# Description....: Get the installation path of a service
# Parameters.....: Service Name
# Return Values..: $true
#                  $false
# =================================================================================================================================
# Save the Services List
Function Get-ServiceInstallPath{
    param ($ServiceName)
    Begin
    {

    }
    Process
    {
        $retInstallPath = $Null
        try
        {
            if ($m_ServiceList -eq $null)
            {
                Set-Variable -Name m_ServiceList -Value $(Get-ChildItem "HKLM:\System\CurrentControlSet\Services" | ForEach-Object { Get-ItemProperty $_.pspath }) -Scope Script
            }
            $regPath = $m_ServiceList | Where-Object { $_.PSChildName -eq $ServiceName }
            If ($regPath -ne $null)
            {
                $retInstallPath = $regPath.ImagePath.Substring($regPath.ImagePath.IndexOf('"'), $regPath.ImagePath.LastIndexOf('"') + 1)
            }
        }
        catch
        {
            Throw $(New-Object System.Exception ("Cannot get Service Install path for $ServiceName", $_.Exception))
        }

        return $retInstallPath
    }
    End
    {

    }
}

#region Prerequisites methods
# @FUNCTION@ ======================================================================================================================
# Name...........: CheckNoRDS
# Description....: Check if RDS is installed before the connector is installed
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CheckNoRDS
{
	[OutputType([PsCustomObject])]
	param ()

    Write-LogMessage -Type Verbose -Msg "Starting CheckNoRDS..."

    $global:REGKEY_PSMSERVICE = "Cyber-Ark Privileged Session Manager"
    #If PSM is already installed, there is no need to run this check, since PSM can't be installed without RDS, we can assume RDS is installed.
    $global:m_ServiceList = $null
    if ($(Get-ServiceInstallPath $REGKEY_PSMSERVICE) -eq $null){
	    try{
	    	$errorMsg = ""
	    	$result = $True
	    	$actual = (Get-WindowsFeature Remote-Desktop-Services).InstallState -eq "Installed"
	    	If($actual -eq $True)
	    	{
	    		$result = $False
	    		$errorMsg = "RDS shouldn't be deployed before CyberArk is installed, remove RDS role and make sure there are no domain level GPO RDS settings applied (rsop.msc). Please note, after you remove RDS and restart you may need to use 'mstsc /admin' to connect back to the machine."
	    	}
	    } catch {
	    	$errorMsg = "Could not check RDS installation. Error: $(Collect-ExceptionMessage $_.Exception)"
	    }
    }
    Else{
    $result = $true
    $actual = $true
    $errorMsg = ""
    }

    Write-LogMessage -Type Verbose -Msg "Finished CheckNoRDS"
		
	return [PsCustomObject]@{
		expected = $False;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}      
}


# @FUNCTION@ ======================================================================================================================
# Name...........: PrimaryDNSSuffix
# Description....: Check if machine has Primary DNS Suffix configured
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function PrimaryDNSSuffix
{
	[OutputType([PsCustomObject])]
	param ()
		Write-LogMessage -Type Verbose -Msg "Starting PrimaryDNSSuffix..."
		$errorMsg = ""
		$result = $True
        $PrimaryDNSSuffix = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tcpip\Parameters | select -ExpandProperty Domain
		$actual = $PrimaryDNSSuffix -eq $env:userdnsdomain
		If($actual -eq $True)
		{
			$result = $True
		}
        else
        {
            $result = $False
            $errorMsg = "The logged in user domain: '$($env:userdnsdomain)' doesn't match the machine domain: '$PrimaryDNSSuffix'. Please see KB '000020063' on the customer support portal. (If this machine is not domain joined you need to run the script with -OutOfDomain Flag)."
        }
		Write-LogMessage -Type Verbose -Msg "Finished PrimaryDNSSuffix"
		
	return [PsCustomObject]@{
		expected = $False;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}      
}

# @FUNCTION@ ======================================================================================================================
# Name...........: OSVersion
# Description....: Check the required local machine OS version
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function OSVersion
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting OSVersion..."
		$actual = (Get-CimInstance Win32_OperatingSystem).caption
		$errorMsg = ""
		$result = $false
		
		If($actual -Like '*2016*' -or $actual -like '*2019*' -or $actual -like '*2022*')
		{
			$result = $true
		}
		elseif($actual -Like '*2012 R2*')
		{
			$errorMsg = "Privileged Cloud installation must be run on Windows Server 2019+."   
			$result = $false
		}
		else
		{
			$result = $false
		}
		Write-LogMessage -Type Verbose -Msg "Finished OSVersion"
	} catch {
		$errorMsg = "Could not get OS Version. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "Windows Server 2016/2019/2022";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Secondary Logon
# Description....: Check if Secondary Logon Service is running
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SecondaryLogon
{
	[OutputType([PsCustomObject])]
	param ()

		Write-LogMessage -Type Verbose -Msg "Starting SecondaryLogon..."
		$actual = ""
		$result = $false
		$errorMsg = ""
	
		$actual = (Get-Service -Name seclogon | select -ExpandProperty Status) -eq 'Running'

		If($actual -eq $True)
		{
			$result = $actual
			
		}
		else 
		{
			$actual = $actual
			$result = $actual
            $errorMsg = "Make sure 'Secondary Logon' Service is running, it is required for PSMShadowUsers to invoke Apps/WebApps. You can do it by rerunning the script with -Troubleshooting flag and selecting 'Enable SecondaryLogon Service'"
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished SecondaryLogon"

	return [PsCustomObject]@{
		expected = "True";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: KUsrInitDELL
# Description....: Check if the file KUsrInit.exe exists, indicating Dell Agent was deployed, Meaning Applocker need to whitelist it. 
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function KUsrInitDELL
{
	[OutputType([PsCustomObject])]
	param ()

		Write-LogMessage -Type Verbose -Msg "Starting KUsrInitDELL..."
		$actual = ""
		$result = $false
		$errorMsg = ""
	
		$actual = Test-Path C:\Windows\System32\KUsrInit.exe

		If($actual -eq $True)
		{
			$result = $actual
			$errorMsg = "File C:\Windows\System32\KUsrInit.exe detected! This means DELL agent is deployed and replaced the default UserInit file, you will need to remember to whitelist this file after installation in the PSM Applocker settings. This error will act as a reminder, if you want the script to ignore it, edit the $PSMConfigFile and put 'disabled' under KUsrInit."
            $KUsInit = 'true'
            $parameters = Import-CliXML -Path $CONFIG_PARAMETERS_FILE            
            if (-not($parameters.contains("KUsrInit"))){ #if doesn't contain the value, then we delete existing file and create new 
            Remove-Item -Path $CONFIG_PARAMETERS_FILE
            $parameters += @{KUsrInit = $KUsInit}
            $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII -Force
            }
            #If user changed the value manually in the file to false, we stop bugging him about this error.
            if($parameters.KUsrInit -eq "disabled"){
            $actual = $false
            $result = $true
            $errorMsg = ''
            }
            
		}
		else 
		{
			$actual = $actual
			$result = $true
            
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished KUsrInitDELL"

	return [PsCustomObject]@{
		expected = "false";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: DotNet
# Description....: Check if DotNet 4.8 or higher is installed.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
function DotNet()
{
	[OutputType([PsCustomObject])]
	param ()

	Write-LogMessage -Type Verbose -Msg "Starting DotNet..."
	$minimumDotNetVersionSupported = '528040'
    $expected = ".Net 4.8 is installed"
    $actual = ".Net 4.8 is not installed"
    $result = $false
    $errorMsg = ''

    try 
	{	
		# Read the .NET release version form the registry
		$dotNetRegKey = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
		
		# Check if the version is greater than the minium supported (if the Release key is not avilable , it's less than 4.5)
		if (($dotNetRegKey.Release -eq $null) -or ($dotNetRegKey.Release -lt $minimumDotNetVersionSupported))
		{		
			$actual = ".NET 4.8 is not installed"
            $result = $false
            $errorMsg = ".NET 4.8 or higher is needed for version 12.1+ of CPM/PSM, download it from https://go.microsoft.com/fwlink/?linkid=2088631"
		}
		else
		{
			$actual = $expected
			$result = $true
		}
	}
    catch
	{
		$actual = ".NET 4.8 is not installed"
		$result = $false
	}
    
		Write-LogMessage -Type Verbose -Msg "Finished DotNet"

    [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}	

# @FUNCTION@ ======================================================================================================================
# Name...........: DomainUser
# Description....: Check if the user is a Domain user
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function DomainUser
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting DomainUser..."
		$result = $false
		
		if ($OutOfDomain) 
		{
			$errorMsg = $g_SKIP
			$result = $true
		}
		else
		{
            
            Try{
                Add-Type -AssemblyName System.DirectoryServices.AccountManagement
			    $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
                if($UserPrincipal.ContextType -eq "Domain"){
                    $errorMsg = ''
				    $actual = "Domain user"
				    $result = $true
			}
			else 
			{
				$actual = $false
				$result = $false
                $errorMsg = "Not Domain User"
			}
}
            Catch{
            $result = $false
            $errorMsg = $_.Exception.InnerException.Message
            $actual = $false
            }
		}

		Write-LogMessage -Type Verbose -Msg "Finished DomainUser"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "Domain User";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PendingRestart
# Description....: Check if the machine has pending restarts
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function PendingRestart
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting PendingRestart..."
		$actual = ""
		$result = $false

		$regComponentBasedServicing = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' | Where-Object { $_.Name -match "RebootPending" })
		$regWindowsUpdate = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' | Where-Object { $_.Name -match "RebootRequired" })
		$regSessionManager = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations' -ErrorAction Ignore)
		# SCCM always returns a value back, so we check it's not true instead.
		$wmiClientUtilities = (Invoke-CimMethod -Namespace "Root\CCM\ClientSDK" -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Ignore).RebootPending
		
		$chkComponentBasedServicing = ($null -ne $regComponentBasedServicing)
		$chkWindowsUpdate =	($null -ne $regWindowsUpdate)
		$chkSessionManager = ($null -ne $regSessionManager)
		
		if ($chkComponentBasedServicing -or $chkWindowsUpdate -or $chkSessionManager -or ($wmiClientUtilities -eq $true))
		{
			$actual = $true
			$result = $false
			$errorMsg = "Pending restart detected, restart and run the script again."
		}		
		else
		{
			$actual = $false
			$result = $True
			$errorMsg = ""
		}
	
		Write-LogMessage -Type Verbose -Msg "Finished PendingRestart"
	} catch {
		$errorMsg = "Could not check pending restart on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = $false;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PendingRestartRDS
# Description....: Check if the machine has pending restarts
# Parameters.....: None
# Return Values..: Exit
# =================================================================================================================================
Function PendingRestartRDS
{
	try{
		Write-LogMessage -Type info	-Msg "Checking if machine has pending restart..." -early

		$regComponentBasedServicing = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\' | Where-Object { $_.Name -match "RebootPending" })
		$regWindowsUpdate = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\' | Where-Object { $_.Name -match "RebootRequired" })
		$regSessionManager = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations' -ErrorAction Ignore)
		# SCCM always returns a value back, so we check it's not true instead.
		$wmiClientUtilities = (Invoke-CimMethod -Namespace "Root\CCM\ClientSDK" -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Ignore).RebootPending
		
		$chkComponentBasedServicing = ($null -ne $regComponentBasedServicing)
		$chkWindowsUpdate =	($null -ne $regWindowsUpdate)
		$chkSessionManager = ($null -ne $regSessionManager)
		
		if ($chkComponentBasedServicing -or $chkWindowsUpdate -or $chkSessionManager -or ($wmiClientUtilities -eq $true))
		{
			Write-LogMessage -Type Warning -Msg "Pending restart detected, restart and run the script again."
			Pause
			Exit
		}		
		else
		{
			Write-LogMessage -Type info	-Msg "No pending restart." -early
		}
	} catch {
		$errorMsg = "Could not check pending restart on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: UsersLoggedOn
# Description....: Check how many users are connected to the machine
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function UsersLoggedOn
{
	[OutputType([PsCustomObject])]
	param ()
    $actual = ""
    $errorMsg = ""
    $result = $false
        
	try{
		Write-LogMessage -Type Verbose -Msg "Starting UsersLoggedOn..."
		
		$numOfActiveUsers = (query.exe user /server $($env:COMPUTERNAME) | select-object -skip 1 | measure).Count

		if($numOfActiveUsers -gt 1)
		{
			$actual = $numOfActiveUsers
			$errorMsg = "Check how many users logged on through Task Manager"
			$result = $False
		}
		else
		{
			$actual = "1"
			$result = $True
		}
	}catch{
		Write-LogMessage -Type Error -Msg "Cannot check if another user is logged on"
		$errorMsg = $g_SKIP
		$result = $false
	}
	
	Write-LogMessage -Type Verbose -Msg "Finished UsersLoggedOn"
	
    return [PsCustomObject]@{
        expected = "1";
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: MinimumDriveSpace
# Description....: Check if machine has enough storage space to support deployments.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function MinimumDriveSpace
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting MinimumDriveSpace..."
		[int]$minimumSpace = 10 # 10GB minimum space required.

		$expected = $minimumSpace;
		$actual = ""
		$result = $false
		$errorMsg = ""

		# Get drive C and convert to GB.
		$drivespaceC = Get-PSDrive C
		[int]$actual = [math]::Round($drivespaceC.Free / 1GB)
		
		if ($actual -le $minimumSpace)
		{
			$actual = $actual
			$result = $false
			$errorMsg = "Current free space on Drive C: '$($actual)' GB. We need at least '$($minimumSpace)' GB to guarantee successful download and unpacking of the files."
		}
		else {
			$result = $true
		}
	
		Write-LogMessage -Type Verbose -Msg "Finished MinimumDriveSpace"
	} catch {
		$errorMsg = "Could not check MinimumDriveSpace. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: GPO-Local
# Description....: Check the GPOs on the machine, this check is needed to install RDS otherwise windows blocks it.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function GPO-Local
{
	[OutputType([PsCustomObject])]
	param ()
	[int]$script:gpoRDSerrorsfound = 0
	try{
		Write-LogMessage -Type Verbose -Msg "Starting GPO-Local..."
		$actual = ""	
		$errorMsg = ""
		$result = $false
		$gpoResult = $false
		$compatible = $true

		$path = "C:\Windows\temp\GPOReport.xml"
		gpresult /f /x $path *> $null

		[xml]$xml = Get-Content $path
        
        $computerResults = $xml.Rsop.ComputerResults
        $extensionData = $computerResults.ExtensionData
        $extension = $extensionData.Extension
        $allPolicyNodes = $extension.Policy

        $RDSGPOs = $allPolicyNodes | Where-Object { $_.Category -match "Windows Components" }

		if($RDSGPOs.Category.Count -gt 0)
		{
			ForEach($item in $RDSGPOs)
			{
                
                # Determine source GPO (Domain or Local)
                $gpoDomain = $item.GPO.Domain.'#text'
                $GPOlocation = if ($gpoDomain) { "$gpoDomain Domain" } else { "Local" }

                If($GPOlocation -eq "Local"){                   
				    $skip = $false
				    $name = "GPO-Local: $($item.Name)"
				    $errorMsg = ""	
				    # Check if Generic GPO exists in the critical GPO items, the rest will be caught by below check.
				    If($arrGPOGeneric -match $item.name)
				    {
				    	[int]$script:gpoRDSerrorsfound = 1
				    	$expected = $($arrGPOGeneric -match $item.name).Expected
				    	$gpoResult = ($Expected -eq $($item.state))
				    	if(-not $gpoResult )
				    	{
				    		$compatible = $false
				    		$errorMsg = "Source GPO: $GPOlocation Expected:"+$Expected+" Actual:"+$($item.state)
				    	}
				    }
				    # Check if GPO exists in RDS area (this also catches all PSM critical ones)
				    elseif($item.Category -match "Remote Desktop Services")
				    {
				    	[int]$script:gpoRDSerrorsfound = 1
				    	$expected = 'Not Configured'
				    	$compatible = $false
				    	$errorMsg = "Source GPO: $GPOlocation Expected:'Not Configured' Actual:"+$($item.state)
				    }
				    else {
				    	$skip = $true
				    }
				    if(!$skip)
				    {
                        # If not skip, add the findings to a table.
				    	Write-LogMessage -Type Verbose -Msg ("{0}; Expected: {1}; Actual: {2}" -f $name, $Expected, $item.state)
				    	$reportObj = @{expected = $expected; actual = $($item.state); errorMsg = $errorMsg; result = $gpoResult;}
				    	AddLineToTable $name $reportObj
				    }
                }
			}
		}

		$errorMsg = $g_SKIP
		if(!$compatible)
		{
			 $actual = "RDS will fail"
			 $result = $false
             $errorMsg = "Must remove any local RDS related GPOs before we can deploy the RDS role."
		}
		else
		{
		   $result = $true
		}
	} catch {
		$errorMsg = "Could not check GPO settings on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = "RDS will succeed";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: GPO-Domain
# Description....: Check the GPOs on the machine, this check differs as it only looks for problematic GPOs for PSM functionality.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function GPO-Domain
{
	[OutputType([PsCustomObject])]
	param ()
	# [int]$script:gpoRDSerrorsfound = 0 # shouldn't init this twice, it will overwrite the local one.
	try{
		Write-LogMessage -Type Verbose -Msg "Starting GPO-Domain..."
		$actual = ""	
		$errorMsg = ""
		$result = $false
		$gpoResult = $false
		$compatible = $true

		$path = "C:\Windows\temp\GPOReport.xml"
		#gpresult /f /x $path *> $null # we already run this previously with the local gpo.

		[xml]$xml = Get-Content $path
        
        $computerResults = $xml.Rsop.ComputerResults
        $extensionData = $computerResults.ExtensionData
        $extension = $extensionData.Extension
        $allPolicyNodes = $extension.Policy

        $RDSGPOs = $allPolicyNodes | Where-Object { $_.Category -match "Windows Components" }

		if($RDSGPOs.Category.Count -gt 0)
		{
			ForEach($item in $RDSGPOs)
			{
                
                # Determine source GPO (Domain or Local)
                $gpoDomain = $item.GPO.Domain.'#text'
                $GPOlocation = if ($gpoDomain) { "$gpoDomain Domain" } else { "Local" }

                #domain
                If($gpoDomain){
				    $skip = $false
				    $name = "GPO-Domain: $($item.Name)"
				    $errorMsg = ""	
				    # Check if PSM GPO exists in the critical GPO items
				    If($arrGPOPSM -match $item.name)
				    {
				    	#[int]$script:gpoRDSerrorsfound = 1 # not needed, it won't break RDS
				    	$expected = $($arrGPOPSM -match $item.name).Expected
				    	$gpoResult = ($Expected -eq $($item.state))
				    	if(-not $gpoResult )
				    	{
				    		$compatible = $false
				    		$errorMsg = "Source GPO: $GPOlocation Expected:"+$Expected+" Actual:"+$($item.state)
							$errorMSgSPecific = "Must remove problematic domain GPOs for PSM sessions to succeed."
				    	}
				    }
					# Check if Generic GPO exists in the critical GPO items
					ElseIf($arrGPOGeneric -match $item.name)
					{
						[int]$script:gpoRDSerrorsfound = 1
				    	$expected = $($arrGPOGeneric -match $item.name).Expected
				    	$gpoResult = ($Expected -eq $($item.state))
				    	if(-not $gpoResult )
				    	{
				    		$compatible = $false
				    		$errorMsg = "Source GPO: $GPOlocation Expected:"+$Expected+" Actual:"+$($item.state)
							$errorMSgSPecific = "Must remove problematic domain GPOs for RDS installation to succeed."
				    	}
					}
				    else {
				    	$skip = $true
				    }
				    if(!$skip)
				    {
                        # If not skip, add the findings to a table.
				    	Write-LogMessage -Type Verbose -Msg ("{0}; Expected: {1}; Actual: {2}" -f $name, $Expected, $item.state)
				    	$reportObj = @{expected = $expected; actual = $($item.state); errorMsg = $errorMsg; result = $gpoResult;}
				    	AddLineToTable $name $reportObj
				    }
                }
			}		
		}

		$errorMsg = $g_SKIP
		if(!$compatible)
		{
			 $actual = "Domain GPOs found"
			 $result = $false
             $errorMsg = $errorMSgSPecific
		}
		else
		{
		   $result = $true
		}
	} catch {
		$errorMsg = "Could not check GPO settings on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = "Domain GPOs empty";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: VaultConnectivity
# Description....: Vault network connectivity on port 1858
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function VaultConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Runing VaultConnectivity"
    $script:VaultConnectivityOK = $false
	return Test-NetConnectivity -ComputerName $VaultIP -Port 1858
}

# @FUNCTION@ ======================================================================================================================
# Name...........: TunnelConnectivity
# Description....: Tunnel network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function TunnelConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Running TunnelConnectivity"
    return Test-NetConnectivity -ComputerName $TunnelIP -Port 443
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleNETConnectivity
# Description....: Privilege Cloud network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ConsoleNETConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Running ConsoleNETConnectivity"
	return Test-NetConnectivity -ComputerName $g_ConsoleIP -Port 443
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleHTTPConnectivity
# Description....: Privilege Cloud network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ConsoleHTTPConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
		Write-LogMessage -Type Verbose -Msg "Starting ConsoleHTTPConnectivity..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		
		$CustomerGenericGET = 0

        $portalSubDomainURL = $portalURL.Split(".")[0]

        If(![string]::IsNullOrEmpty($portalSubDomainURL)){
		    Try{
		    	$connectorConfigURL = "https://$g_ConsoleIP/connectorConfig/v1?subDomain=$portalSubDomainURL&configItem=environmentFQDN"
		    	$CustomerGenericGET = Invoke-RestMethod -Uri $connectorConfigURL -TimeoutSec 20 -ContentType 'application/json'
		    	If($null -ne $CustomerGenericGET.config)
		    	{
		    		$actual = "200"
		    		$result = $true
		    	}
		    } catch {
		    	if ($_.Exception.Message -eq "Unable to connect to the remote server")
		    	{
		    		$errorMsg = "Unable to connect to the remote server - Unable to GET to '$connectorConfigURL' Try it from your browser."
		    		$result = $false
		    		$actual = $_.Exception.Response.StatusCode.value__
		    	}
		    	elseif ($_.Exception.Message -eq "The underlying connection was closed: An unexpected error occurred on a receive.")
		    	{
		    		$errorMsg = "The underlying connection was closed - Unable to GET to '$connectorConfigURL' Try it from your browser." 
		    		$result = $false
		    		$actual = $_.Exception.Response.StatusCode.value__
		    	}
                elseif ($_.Exception.Response.StatusCode.value__ -eq 400)
		    	{
		    		$errorMsg = "Unable to GET to '$connectorConfigURL' Something is wrong with the syntax we are sending.."
		    		$result = $false
		    		$actual = $_.Exception.Response.StatusCode.value__
		    	}
		    	else
		    	{
		    		$errorMsg = "Could not verify console connectivity. Error: $(Collect-ExceptionMessage $_.Exception)"
		    		$result = $false
		    		$actual = $_.Exception.Response.StatusCode.value__
		    	}
		    }
        }
        Else{
		    $errorMsg = "Skipping this test since host is empty"
        }	
		
		Write-LogMessage -Type Verbose -Msg "Finished ConsoleHTTPConnectivity"
		
	return [PsCustomObject]@{
		expected = "200";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConsoleHTTPConnectivity
# Description....: Privilege Cloud network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SecureTunnelLocalPort
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting SecureTunnelLocalPort..."
		$actual = ""
		$result = $false
		$errorMsg = ""
        $expected = "Empty"
		
		$lclPort = Get-NetTCPConnection | Where-Object {$_.LocalPort -eq 50000 -or $_.LocalPort -eq 50001}
		if ($lclPort -eq $null)
		{
			  $actual = $expected
			  $result = $True
		}
        ElseIf((get-process -Id ($lclport).OwningProcess).ProcessName -eq "PrivilegeCloudSecureTunnel"){
              $result = $True
        }
		else 
		{
			  $actual = (get-process -Id ($lclport).OwningProcess).ProcessName
			  $result = $false
			  $errorMsg = "LocalPort 50000/50001 is taken by --> " + (get-process -Id ($lclport).OwningProcess).ProcessName + " <-- This port is needed for SecureTunnel functionality, if you're not going to install it you can disregard this error, otherwise we suggest checking what process is using it"
		}

		Write-LogMessage -Type Verbose -Msg "Finished SecureTunnelLocalPort"
	} catch {
		$errorMsg = "Could not check LocalPorts. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CRLConnectivity
# Description....: CRL connectivity
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CRLConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting CRLConnectivity..."
		$actual = ""
		$result = $false
		$errorMsg = ""

		$cert = 0


			$cert = Invoke-WebRequest -Uri http://ocsp.digicert.com -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing  | Select-Object -ExpandProperty StatusCode

			If($cert -eq 200)
			{
				$actual = "200"
				$result = $true
            }

		Write-LogMessage -Type Verbose -Msg "Finished CRLConnectivity"
	} catch {
		$errorMsg = "Could not verify CRL connectivity, Check DNS/FW. Error: $(Collect-ExceptionMessage $_.Exception.Message)"
	}
		
	return [PsCustomObject]@{
		expected = "200";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CustomerPortalConnectivity
# Description....: Privilege Cloud Console network connectivity on port 443
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CustomerPortalConnectivity
{
	[OutputType([PsCustomObject])]
	param ()
	Write-LogMessage -Type Verbose -Msg "Starting CustomerPortalConnectivity"

    return Test-NetConnectivity -ComputerName $PortalURL -Port 443
    Write-LogMessage -Type Verbose -Msg "Finished CustomerPortalConnectivity"
}

# @FUNCTION@ ======================================================================================================================
# Name...........: IdentityGlobalSign
# Description....: CRL connectivity
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function IdentityGlobalSign
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting IdentityGlobalSign..."
		$actual = ""
		$result = $false
		$errorMsg = ""

        $globalsignURLs = @("ocsp.globalsign.com","crl.globalsign.com","secure.globalsign.com")
        
        foreach($globalsignurl in $globalsignURLs)
        {
            $cert = 0
            $cert = Invoke-WebRequest -Uri $globalsignurl -TimeoutSec 6 -ErrorAction SilentlyContinue -WarningAction SilentlyContinue -UseBasicParsing  | Select-Object -ExpandProperty StatusCode
            If($cert -eq 200)
            {
                $actual = "200"
            	$result = $true
            }Else{
                $actual = $cert
                #$errorMsg = "Could not verify connectivity, Check DNS/FW. Error: $(Collect-ExceptionMessage $_.Exception.Message)"
            }
        }

		Write-LogMessage -Type Verbose -Msg "Finished IdentityGlobalSign"
	} catch {
		$errorMsg = "Could not verify connectivity, Check DNS/FW. Error: $(Collect-ExceptionMessage $_.Exception.Message)"
	}
		
	return [PsCustomObject]@{
		expected = "200";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Processors
# Description....: Minimum required CPU cores
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function Processors
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting Processors..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		
		$cpuNumber = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
		if ($cpuNumber -ge "8")
		{
			  $actual = $cpuNumber
			  $result = $True
		} 
		else 
		{
			  $actual = $cpuNumber
			  $result = $false
			  $errorMsg = "Less than minimum (8) cores detected"
		}

		Write-LogMessage -Type Verbose -Msg "Finished Processors"
	} catch {
		$errorMsg = "Could not check minimum required Processors. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Memory
# Description....: Minimum required Memory
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function Memory
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting Memory..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		$Memory = Try{[math]::Round(((Get-CimInstance CIM_PhysicalMemory).Capacity | Measure-Object -Sum).Sum / 1GB, 2)}Catch{}
		$MemoryAWS = Try{[math]::Round((Get-CimInstance -ClassName CIM_ComputerSystem).TotalPhysicalMemory / 1GB, 0)}Catch{}

		if ($Memory -ge 8 -or $MemoryAWS -ge 8)
		{
			  $actual = $Memory
			  $result = $True
		} 
		else 
		{
			  $actual = $Memory
			  $result = $false
			  $errorMsg = "Less than minimum (8) RAM detected"
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished Memory"
	} catch {
		$errorMsg = "Could not check minimum required memory. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}	

# @FUNCTION@ ======================================================================================================================
# Name...........: SQLServerPermissions
# Description....: Required SQL Server permissions for successful RDS install on OS 2016, not relevant from 2019+.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SQLServerPermissions
{
	[OutputType([PsCustomObject])]
	param ()
		Write-LogMessage -Type Verbose -Msg "Starting SQLServerPermissions..."
		$actual = ""
		$result = $False
		$errorMsg = ""

        $OS = (Get-CimInstance Win32_OperatingSystem).caption

    # Check if we are on 2016, other OS don't need this check.
  if($OS -Like '*2016*'){
    Try{
		$SecPolGPO = @{
			"SeDebugPrivilege" = "Debug Programs";
			"SeBackupPrivilege" = "Back up files and directories";
			"SeSecurityPrivilege" = "Manage auditing and security log";
		}

		$path = "C:\Windows\Temp\SecReport.txt"
		SecEdit /areas USER_RIGHTS /export /cfg $path

		ForEach ($sec in $SecPolGPO.Keys) 
		{
			Write-LogMessage -Type Verbose -Msg "Checking $sec group policy for Local Administrators access"
			$administrators = Select-String $path -Pattern $sec
			if($null -eq $administrators)
			{
				Write-LogMessage -Type Verbose -Msg "No Local Administrators access for $sec group policy"
				$actual = $result = $False
				$errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
			}
			else
			{
				foreach ($admin in $administrators)
				{
					if ($admin -like "*S-1-5-32-544*")
					{
						Write-LogMessage -Type Verbose -Msg "$sec group policy has Local Administrators access"
						$actual = $True
                        $result = $True
					}
					else
					{
						Write-LogMessage -Type Verbose -Msg "No Local Administrators access for $sec group policy"
						$actual = $False
                        $result = $False
                        $errorMsg = "Missing administrators in Group Policy: " + $SecPolGPO[$sec]
                        $missingGroup = $true
					}
                 # if even one of the groups was missing we need to declare final error as RED.
                 if($missingGroup){
                    $actual = $False
                    $result = $False
                 }
				}
			}
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished SQLServerPermissions"
	} catch {
		$errorMsg = "Could not check SQL Server permissions. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
  }Else{
    $actual = $True
    $result = $True
  }
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: LogonAsaService
# Description....: Logon as service permissions
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function LogonAsaService
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting LogonAsaService..."
		$actual = ""
		$result = $False
		$errorMsg = ""

		$SecPolGPO = @{
			"SeServiceLogonRight" = "Log on as a service";
		}

		$path = "C:\Windows\Temp\SecReport.txt"
		SecEdit /areas USER_RIGHTS /export /cfg $path

		ForEach ($sec in $SecPolGPO.Keys) 
		{
			Write-LogMessage -Type Verbose -Msg "Checking $sec group policy for access"
			$logonasAserviceUsers = Select-String $path -Pattern $sec
			if($null -eq $logonasAserviceUsers)
			{
				Write-LogMessage -Type Verbose -Msg "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
				$actual = $result = $False
				$errorMsg = "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
			}
			else
			{
				foreach ($logonUser in $logonasAserviceUsers)
				{
					if ($logonUser -like "*S-1-5-20*")
					{
						Write-LogMessage -Type Verbose -Msg "$sec group policy has access"
						$actual = $result = $True
					}
					else
					{
						Write-LogMessage -Type Verbose -Msg "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
						$actual = $result = $False
						$errorMsg = "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
					}
				}
			}
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished LogonAsaService"
	} catch {
		$errorMsg = "Missing NETWORK SERVICE in Group Policy: " + $SecPolGPO[$sec]
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: InterActiveLoginSmartCardIsDisabled
# Description....: Check that no smart card is required to RDP to the machine
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function InterActiveLoginSmartCardIsDisabled
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting InterActiveLoginSmartCardIsDisabled..."
		$actual = ""
		$result = $False
		$errorMsg = ""
        $expected = $true

		$secOptionspath = "C:\Windows\Temp\SecReport.txt"
		SecEdit /areas securitypolicy /export /cfg $secOptionspath | Out-Null

        $secOptionsValue = Get-Content $secOptionspath
		$SmartCardIsEnabled = $secOptionsValue | Select-String -SimpleMatch 'MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\ScForceOption=4,1'
        #if returns some value, it means its enabled (User will received CredSSP error during ansible install).
        if($SmartCardIsEnabled -ne $null){
            $result = $false
		    $errorMsg = "Please disable `"GPO: Interactive logon: Require Smart card`""
            $actual = $false
        }
        Else{
            $result = $True
		    $errorMsg = ""
            $actual = $True
        }
		
		Write-LogMessage -Type Verbose -Msg "Finished InterActiveLoginSmartCardIsDisabled"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

#endregion

#region Helper functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Test-NetConnectivity
# Description....: Network connectivity to a specific Hostname/IP on a specific port
# Parameters.....: ComputerName, Port
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function Test-NetConnectivity
{
	[OutputType([PsCustomObject])]
	param(
		[string]$ComputerName,
		[int]$Port
	)
	$errorMsg = "Network connectivity failed, check FW rules to '$ComputerName' on port '$Port' are allowed"
	$result = $False
	If(![string]::IsNullOrEmpty($ComputerName)) # -and ![string]::IsNullOrEmpty($portalSubDomainURL))
	{
		try{
			If(Get-Command Test-NetConnection -ErrorAction Ignore)
			{
				$retNetTest = Test-NetConnection -ComputerName $ComputerName -Port $Port -WarningVariable retWarning | Select-Object -ExpandProperty "TcpTestSucceeded"
				If($retWarning -like "*TCP connect to* failed" -or $retWarning -like "*Name resolution of*")
				{
					$errorMsg = "Network connectivity failed, check FW rules to '$ComputerName' on port '$Port' are allowed"
					$result = $False
				}
				Else { 
                     $result = $True
                     # if port 1858, indicating vault test, declare param so we can use it in CPMConnectionTest.
                     if($port -eq 1858){$script:VaultConnectivityOK = $True}
                     $errorMsg = ""
                     }
			}
			Else
			{
				# For OS with lower PowerShell version or Windows 2012
				$tcpClient = New-Object Net.Sockets.TcpClient
				$tcpClient.ReceiveTimeout = $tcpClient.SendTimeout = 2000;
				# We use Try\Catch to remove exception info from console if we can't connect
				try { 
					$tcpClient.Connect($ComputerName,$Port) 
					$retNetTest = $tcpClient.Connected
					if($retNetTest)
					{
						$tcpClient.Close()
						$result = $True
                        $errorMsg = ""
					}
					else
					{
						$errorMsg = "Network connectivity failed, check FW rules to '$ComputerName' on port '$Port' are allowed"
						$result = $False
					}
				} catch {}
			}
		} catch {
			$errorMsg = "Could not check network connectivity to '$ComputerName'. Error: $(Collect-ExceptionMessage $_.Exception)"
		}
	}
	Else
	{
		$retNetTest = $False
		Write-LogMessage -Type Info -Msg "Skipping network test since host name is empty"
		$errorMsg = "Host name empty"
	}
	
	return [PsCustomObject]@{
		expected = $True;
		actual = $retNetTest;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-UserPrincipal
# Description....: Returns the Current User Principal object
# Parameters.....: None
# Return Values..: Current User Principal
# =================================================================================================================================
Function Get-UserPrincipal
{
	try { [System.DirectoryServices.AccountManagement] -as [type] }
	catch { Add-Type -AssemblyName System.DirectoryServices.AccountManagement }
	return [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
}

# @FUNCTION@ ======================================================================================================================
# Name...........: IsUserAdmin
# Description....: Check if the user is a Local Admin
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function IsUserAdmin()
{
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    return (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.SecurityIdentifier] "S-1-5-32-544")  # Local Administrators group SID
}

# @FUNCTION@ ======================================================================================================================
# Name...........: GetPublicIP
# Description....: Returns the public IP of the machine
# Parameters.....: None
# Return Values..: String, Public IP Address of local machine
# =================================================================================================================================
Function GetPublicIP()
{
	$PublicIP = ""

	try{
		Write-LogMessage -Type Info -Msg "Attempting to retrieve Public IP..." -Early
		$PublicIP = (Invoke-WebRequest -Uri ipinfo.io/ip -UseBasicParsing -TimeoutSec 5).Content
		$PublicIP | Out-File "_$($env:COMPUTERNAME) PublicIP.txt"
		Write-LogMessage -Type Success -Msg "Successfully fetched Public IP: $PublicIP and saved it in a local file '$($env:COMPUTERNAME) PublicIP.txt'"
		return $PublicIP
	}
	catch{
		Write-LogMessage -Type Info -Msg "GetPublicIP: Couldn't grab Public IP for you, you'll have to do it manually: $(Collect-ExceptionMessage $_.Exception.Message)" -Early
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: MachineNameCharLimit
# Description....: Checks if Machine has name longer than 15 char MS limit.
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function MachineNameCharLimit()
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting MachineNameCharLimit..."
		$actual = ""
		$result = $False
		$errorMsg = ""
        $expected = $true

		[int]$MachineCharLength = (hostname).length
		
        
        #Check if machine name is over 15 chars.
        if($MachineCharLength -gt 15){
            $result = $false
		    $errorMsg = "Computer hostname is over 15 char limit."
            $actual = $MachineCharLength
        }
        Else{
            $result = $True
		    $errorMsg = ""
        }
		
		Write-LogMessage -Type Verbose -Msg "Finished MachineNameCharLimit"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CheckIdentityCustomURL
# Description....: Checks with a dummy account if identity vanity url is enabled. (Expected false, since not supported in privcloud yet).
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function CheckIdentityCustomURL{
	[OutputType([PsCustomObject])]
	param ()

    Write-LogMessage -Type Verbose -Msg "Starting CheckIdentityCustomURL..."

    $expected = $true
    $result = $false
    $errorMsg = ""
    $actual = ""

    $portalSubDomainURL = $portalURL.Split(".")[0]

    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($portalSubDomainURL)){
        Try{
        	# PlatformParams
	    	$BasePlatformURL = "https://$portalSubDomainURL.cyberark.cloud"
	    	# Retrieve Identity from redirect
            $IdentityHeaderURL = Get-IdentityURL -idURL $BasePlatformURL
            if($IdentityHeaderURL -like "*Error*"){
                $errorMsg = "Error accessing URL '$($BasePlatformURL)' $($IdentityHeaderURL)"
                $result = $false
                $actual = $false
            }Else{
	    	    $IdaptiveBasePlatformURL = "https://$IdentityHeaderURL"
	    	    $IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
	    	    $startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
	    	    $startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"

	    	    # Begin Start Authentication Process
                $IdentityTenantId = $IdentityHeaderURL.Split(".")[0]
	    	    $startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = "TestDummyPrereqScript" ; Version = "1.0"} | ConvertTo-Json -Compress
	    	    $IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 10 -ErrorVariable identityErr
	    	    
                if(-not($IdaptiveResponse.Result.Challenges.mechanisms -eq $null))
                {
                    $actual = $true
                    $result = $true

                }
                Else
                {
                    # Tenant has Custom URL enabled, we don't support it yet.
                    if($IdaptiveResponse.Result.PodFqdn){
                        $actual = $false
                        $result = $false
                        $errorMsg = "It looks like you have configured customized URL in Identity Administration, please disable it and try again (more info here: https://docs.cyberark.com/Product-Doc/OnlineHelp/Idaptive/Latest/en/Content/GetStarted/CustomDomain.htm)."
                    }
                    Else
                    {
                        # catch all other errors, just display whatever we see in result.
                        $actual = $IdaptiveResponse.Result
                        $errorMsg = $IdaptiveResponse.Result
                    }                
                }
            }
        Write-LogMessage -Type Verbose -Msg "Finished CheckIdentityCustomURL..."
        }
        Catch
        {
            $errorMsg = $identityErr.message + $_.exception.status + $_.exception.Response.ResponseUri.AbsoluteUri
        }
    }
	Else
	{
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty"
		$errorMsg = "Host name empty"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: ConnectorManagementScripts
# Description....: Check connectivity to CM(+AWS S3 bucket, IOT).
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function ConnectorManagementScripts{
	[OutputType([PsCustomObject])]
	param ()

    $expected = "403"
    $result = $false
    $errorMsg = ""
    $actual = ""
    Write-LogMessage -Type Verbose -Msg "Starting ConnectorManagementScripts..."


    $portalSubDomainURL = $portalURL.Split(".")[0]

    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($portalSubDomainURL)){
        Try{
	    	$BasePlatformURL = "https://$portalSubDomainURL.cyberark.cloud"
	    	# Retrieve Identity from redirect
            $script:IdentityHeaderURL = Get-IdentityURL -idURL $BasePlatformURL
            if($IdentityHeaderURL -like "*Error*"){
                $errorMsg = "Error accessing URL '$($BasePlatformURL)' $($IdentityHeaderURL)"
            }Else{
                # Find Identity Region
                $script:GetTenantDetails = Invoke-RestMethod -uri "https://$($IdentityHeaderURL)/sysinfo/version" -UseBasicParsing -ErrorVariable respErr

                # Select region Name, so we can match it vs exception regions below
                $searchRegion = $GetTenantDetails.Result.Region

                # Special exception for CM regions operated elsewhere.
                if($searchRegion -eq "Eu South"){
                    $searchRegion = "Frankfurt"
                }
                # Special exception for CM regions operated elsewhere.
                if($searchRegion -eq "ap-southeast-3"){ # Jakarta
                    $searchRegion = "AP Southeast" # Singapore
                }
                # Special exception for CM regions operated elsewhere.
                if($searchRegion -eq "il-central-1"){ # Tel Aviv
                    $searchRegion = "Frankfurt"
                }

                # Special exception for Australia and India since Identity uses same region name for them, we can distinguish by pod
                if($searchRegion -eq "Asia Pacific"){
                    if($GetTenantDetails.Result.Name -like "pod1302*" -or $GetTenantDetails.Result.Name -like "pod1306*")
                    {
                        $searchRegion = "Sydney"
                    }
                    Else{
                        $searchRegion = "Asia Pacific"
                    }
                       
                }

                    # Match region from list and get region code.
                    $script:region = $availableRegions | Where-Object {$_.RegionName -eq $searchRegion -or $_.regionCode -eq $searchRegion} | select -ExpandProperty regionCode
            }


            if([string]::IsNullOrEmpty($region)){
                Write-LogMessage -type Warning -msg "Error retrieving identity region via redirect of '$($BasePlatformURL)': $($IdentityHeaderURL)"
                start-sleep 5
                Write-Host "Select region manually"
                Pause
                $searchRegion = $availableRegions | Out-GridView -PassThru
                $script:region = $availableRegions | Where-Object {$_.RegionName -eq $searchRegion.RegionName} | select -ExpandProperty regionCode
            }

        $CMUrls = @(
            "https://connector-management-scripts-490081306957-$($region).s3.amazonaws.com"
            #"https://connector-management-assets-490081306957-$($region).s3.amazonaws.com",
            #"https://component-registry-store-490081306957.s3.amazonaws.com/"
        )
	    	
                # Start Connectivity test
                foreach($url in $CMUrls){
                Try{
                    Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction SilentlyContinue -TimeoutSec 10 -ErrorVariable respErr
                    }
                Catch
                {
                    if($_.Exception.Response.StatusCode.value__ -eq 403)
                    {
                        if($respErr.message -like "*(403) Forbidden*"){
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $true
                            $errorMsg = ""
                        }
                        Else{
                            # every other error within 403 response.
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $false
                            $errorMsg = "$($respErr)"
                        }
                    }
                    Elseif($respErr -like "*certificate*")
                    {
                        # In case error is related to certificates
                        $actual = $_.Exception.Response.StatusCode.value__
                        $result = $false
                        $errorMsg = "$($respErr.message) $($respErr.innerException.InnerException.Message) | hint: Try browsing to the URL: $($url) and check the certificate icon is secure, if not, You're either blocking it via GPO or FW policy, you can either disable those or copy over all amazon certs from another machine with good access by exporting and then importing. (we recommend solving the issue though)."
                    }
                    Else{
                        # every other error.
                        $errorMsg = "Tried reaching '$($url)', Received Error: $($respErr)"
                        $result = $false
                        $actual = $_.Exception.Response.StatusCode.value__
                    }
                }

            }
     
        Write-LogMessage -Type Verbose -Msg "Finished ConnectorManagementScripts..."
        }
        Catch
        {
            $errorMsg = "Error: $(Collect-ExceptionMessage) $($respErr.message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri)"

        }
    }
	Else
	{
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty"
		$errorMsg = "Host name empty"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}



# @FUNCTION@ ======================================================================================================================
# Name...........: ConnectorManagementAssets
# Description....: Check connectivity to CM(+AWS S3 bucket, IOT).
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function ConnectorManagementAssets{
	[OutputType([PsCustomObject])]
	param ()

    $expected = "403"
    $result = $false
    $errorMsg = ""
    $actual = ""
    Write-LogMessage -Type Verbose -Msg "Starting ConnectorManagementAssets..."


    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($region)){
        Try{
            $CMUrls = @(
            "https://connector-management-assets-490081306957-$($region).s3.amazonaws.com"
            )
	    	
            # Start Connectivity test
            foreach($url in $CMUrls){
                Try{
                    Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction SilentlyContinue -TimeoutSec 10 -ErrorVariable respErr
                    }
                Catch
                {
                    if($_.Exception.Response.StatusCode.value__ -eq 403)
                    {
                        if($respErr.message -like "*(403) Forbidden*"){
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $true
                            $errorMsg = ""
                        }
                        Else{
                            # every other error within 403 response.
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $false
                            $errorMsg = "$($respErr)"
                        }
                    }
                    Elseif($respErr -like "*certificate*")
                    {
                        # In case error is related to certificates
                        $actual = $_.Exception.Response.StatusCode.value__
                        $result = $false
                        $errorMsg = "$($respErr.message) $($respErr.innerException.InnerException.Message) | hint: Try browsing to the URL: $($url) and check the certificate icon is secure, if not, You're either blocking it via GPO or FW policy, you can either disable those or copy over all amazon certs from another machine with good access by exporting and then importing. (we recommend solving the issue though)."
                    }
                    Else{
                        # every other error.
                        $errorMsg = "Tried reaching '$($url)', Received Error: $($respErr)"
                        $result = $false
                        $actual = $_.Exception.Response.StatusCode.value__
                    }
                }
            }
     
        Write-LogMessage -Type Verbose -Msg "Finished ConnectorManagementAssets..."
        }
        Catch
        {
            $errorMsg = "Error: $(Collect-ExceptionMessage) $($respErr.message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri)"

        }
    }
	Else
	{
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty (Previous check probably failed)"
		$errorMsg = "Skipping test since host name is empty (ConnectorManagementScripts failed?)"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: ConnectorManagementComponentRegistry
# Description....: Check connectivity to CM(+AWS S3 bucket, IOT).
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function ConnectorManagementComponentRegistry{
	[OutputType([PsCustomObject])]
	param ()

    $expected = "403"
    $result = $false
    $errorMsg = ""
    $actual = ""
    Write-LogMessage -Type Verbose -Msg "Starting ConnectorManagementComponentRegistry..."


    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($region)){
        Try{
            $CMUrls = @(
            "https://component-registry-store-490081306957.s3.amazonaws.com"
            )
	    	
            # Start Connectivity test
            foreach($url in $CMUrls){
                Try{
                    Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction SilentlyContinue -TimeoutSec 10 -ErrorVariable respErr
                    }
                Catch
                {
                    if($_.Exception.Response.StatusCode.value__ -eq 403)
                    {
                        if($respErr.message -like "*(403) Forbidden*"){
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $true
                            $errorMsg = ""
                        }
                        Else{
                            # every other error within 403 response.
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $false
                            $errorMsg = "$($respErr)"
                        }
                    }
                    Elseif($respErr -like "*certificate*")
                    {
                        # In case error is related to certificates
                        $actual = $_.Exception.Response.StatusCode.value__
                        $result = $false
                        $errorMsg = "$($respErr.message) $($respErr.innerException.InnerException.Message) | hint: Try browsing to the URL: $($url) and check the certificate icon is secure, if not, You're either blocking it via GPO or FW policy, you can either disable those or copy over all amazon certs from another machine with good access by exporting and then importing. (we recommend solving the issue though)."
                    }
                    Else{
                        # every other error.
                        $errorMsg = "Tried reaching '$($url)', Received Error: $($respErr)"
                        $result = $false
                        $actual = $_.Exception.Response.StatusCode.value__
                    }
                }
            }
     
        Write-LogMessage -Type Verbose -Msg "Finished ConnectorManagementComponentRegistry..."
        }
        Catch
        {
            $errorMsg = "Error: $(Collect-ExceptionMessage) $($respErr.message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri)"
        }
    }
	Else
	{
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty (Previous check probably failed)"
		$errorMsg = "Skipping test since host name is empty (ConnectorManagementScripts failed?)"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConnectorManagementIOT
# Description....: Vault network connectivity on port 1858
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ConnectorManagementIOT
{
	[OutputType([PsCustomObject])]
	param ()
    
    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($region)){
        $AwsIOTAddress = "a3vvqcp8z371p3-ats.iot.$($region).amazonaws.com"
	    Write-LogMessage -Type Verbose -Msg "Runing ConnectorManagementIOT"
	    return Test-NetConnectivity -ComputerName $AwsIOTAddress -Port 443
    }
	Else
	{
        # In case $region is empty, we override the entire test and return our own customObject result.
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty (Previous check probably failed)"
		$errorMsg = "Skipping test since host name is empty (ConnectorManagementScripts failed?)"
        $result = $false
        return [PsCustomObject]@{
		expected = $true;
		actual = $false;
		errorMsg = $errorMsg;
		result = $result;
	    }
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ConnectorManagementIOTCert
# Description....: Check the certificate endpoint is not tampered by proxy/SSL inspect.
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
function ConnectorManagementIOTCert {
    [OutputType([PsCustomObject])]
    param ()
    
    $expected = "CN=Amazon RSA 2048 M01, O=Amazon, C=US"
    $result = $false
    $errorMsg = ""
    $actual = ""

    Write-LogMessage -Type Verbose -Msg "Starting ConnectorManagementIOTCert..."
    
    if (![string]::IsNullOrEmpty($Region)) {
        try {
            $CertURL = "https://a3vvqcp8z371p3-ats.iot.$($Region).amazonaws.com:443"
            $cert = Get-SSLCertificateDetails -Url $CertURL
            $actual = $cert.Issuer
            
            if ($actual -ne $expected) {
                $errorMsg = "The expected certificate ('$($expected)') doesn't match the actual certificate received ('$($actual)'). Test it by browsing to this URL: '$($CertURL)'."
            } else {
                $result = $true
            }

            Write-LogMessage -Type Verbose -Msg "Finished ConnectorManagementIOTCert..."
        } catch {
            $errorMsg = "$(Collect-ExceptionMessage) $($errMsg)"
        }
    } else {
        $errorMsg = "Skipping test since host name is empty (ConnectorManagementScripts failed?)"
    }
    
    return [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}

Function DPA-Assets{
	[OutputType([PsCustomObject])]
	param ()

    $expected = "403"
    $result = $false
    $errorMsg = ""
    $actual = ""
    Write-LogMessage -Type Verbose -Msg "Starting DPA-Assets..."


    $portalSubDomainURL = $portalURL.Split(".")[0]

    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($portalSubDomainURL)){
        Try{
	    	$BasePlatformURL = "https://$portalSubDomainURL.cyberark.cloud"
	    	# Retrieve Identity from redirect
            $script:IdentityHeaderURL = Get-IdentityURL -idURL $BasePlatformURL
            if($IdentityHeaderURL -like "*Error*"){
                $errorMsg = "Error accessing URL '$($BasePlatformURL)' $($IdentityHeaderURL)"
            }Else{
                # Find Identity Region
                $script:GetTenantDetails = Invoke-RestMethod -uri "https://$($IdentityHeaderURL)/sysinfo/version" -UseBasicParsing -ErrorVariable respErr

                # Select region Name, so we can match it vs exception regions below
                $searchRegion = $GetTenantDetails.Result.Region

                # Special exception for CM regions operated elsewhere.
                if($searchRegion -eq "Eu South"){
                    $searchRegion = "Frankfurt"
                }
                # Special exception for CM regions operated elsewhere.
                if($searchRegion -eq "ap-southeast-3"){ # Jakarta
                    $searchRegion = "AP Southeast" # Singapore
                }
                # Special exception for CM regions operated elsewhere.
                if($searchRegion -eq "il-central-1"){ # Tel Aviv
                    $searchRegion = "Frankfurt"
                }

                # Special exception for Australia and India since Identity uses same region name for them, we can distinguish by pod
                if($searchRegion -eq "Asia Pacific"){
                    if($GetTenantDetails.Result.Name -like "pod1302*" -or $GetTenantDetails.Result.Name -like "pod1306*")
                    {
                        $searchRegion = "Sydney"
                    }
                    Else{
                        $searchRegion = "Asia Pacific"
                    }
                       
                }

                    # Match region from list and get region code.
                    $script:region = $availableRegions | Where-Object {$_.RegionName -eq $searchRegion -or $_.regionCode -eq $searchRegion} | select -ExpandProperty regionCode
            }


            if([string]::IsNullOrEmpty($region)){
                Write-LogMessage -type Warning -msg "Error retrieving identity region via redirect of '$($BasePlatformURL)': $($IdentityHeaderURL)"
                start-sleep 5
                Write-Host "Select region manually"
                Pause
                $searchRegion = $availableRegions | Out-GridView -PassThru
                $script:region = $availableRegions | Where-Object {$_.RegionName -eq $searchRegion.RegionName} | select -ExpandProperty regionCode
            }

        # Logic for DPA regions, if US east it doesn't require region code in the URL
        if($region -eq "us-east-1"){
            $url = "https://cms-assets-bucket-445444212982.s3.amazonaws.com"
        }Else{
            $url = "https://cms-assets-bucket-445444212982-$($region).s3.$($region).amazonaws.com"
        }
        
	    	
                # Start Connectivity test
                Try{
                    Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction SilentlyContinue -TimeoutSec 10 -ErrorVariable respErr
                    }
                Catch
                {
                    if($_.Exception.Response.StatusCode.value__ -eq 403)
                    {
                        if($respErr.message -like "*(403) Forbidden*"){
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $true
                            $errorMsg = ""
                        }
                        Else{
                            # every other error within 403 response.
                            $actual = $_.Exception.Response.StatusCode.value__
                            $result = $false
                            $errorMsg = "$($respErr)"
                        }
                    }
                    Elseif($respErr -like "*certificate*")
                    {
                        # In case error is related to certificates
                        $actual = $_.Exception.Response.StatusCode.value__
                        $result = $false
                        $errorMsg = "$($respErr.message) $($respErr.innerException.InnerException.Message) | hint: Try browsing to the URL: $($url) and check the certificate icon is secure, if not, You're either blocking it via GPO or FW policy, you can either disable those or copy over all amazon certs from another machine with good access by exporting and then importing. (we recommend solving the issue though)."
                    }
                    Else{
                        # every other error.
                        $errorMsg = "Tried reaching '$($url)', Received Error: $($respErr)"
                        $result = $false
                        $actual = $_.Exception.Response.StatusCode.value__
                    }
                }


     
        Write-LogMessage -Type Verbose -Msg "Finished DPA-Assets..."
        }
        Catch
        {
            $errorMsg = "Error: $(Collect-ExceptionMessage) $($respErr.message) $($_.exception.status) $($_.exception.Response.ResponseUri.AbsoluteUri)"

        }
    }
	Else
	{
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty"
		$errorMsg = "Host name empty"
	}
	
	return [PsCustomObject]@{
		expected = $expected;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

Function DPA-BackendAccess
{
	[OutputType([PsCustomObject])]
	param ()
    
    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($region)){
        $dpabeaddress = "$($region).bc.be-privilege-access.cyberark.cloud"
	    Write-LogMessage -Type Verbose -Msg "Runing DPA-BackendAccess"
	    return Test-NetConnectivity -ComputerName $dpabeaddress -Port 443
    }
	Else
	{
        # In case $region is empty, we override the entire test and return our own customObject result.
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty (Previous check probably failed)"
		$errorMsg = "Skipping test since host name is empty (DPA-Assets failed?)"
        $result = $false
        return [PsCustomObject]@{
		expected = $true;
		actual = $false;
		errorMsg = $errorMsg;
		result = $result;
	    }
	}
}

Function DPA-Portal
{
	[OutputType([PsCustomObject])]
	param ()
    
    $portalSubDomainURL = $portalURL.Split(".")[0]

    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($region)){
        $dpabeaddress = "$($portalSubDomainURL).dpa.cyberark.cloud"
	    Write-LogMessage -Type Verbose -Msg "Runing DPA-Portal"
	    return Test-NetConnectivity -ComputerName $dpabeaddress -Port 443
    }
	Else
	{
        # In case $region is empty, we override the entire test and return our own customObject result.
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty (Previous check probably failed)"
		$errorMsg = "Skipping test since host name is empty (DPA-Assets failed?)"
        $result = $false
        return [PsCustomObject]@{
		expected = $true;
		actual = $false;
		errorMsg = $errorMsg;
		result = $result;
	    }
	}
}


Function DPA-IOT
{
	[OutputType([PsCustomObject])]
	param ()

    # skip check if portalUrl is empty
    if(![string]::IsNullOrEmpty($region)){
        $AwsIOTAddress = "a2m4b3cupk8nzj-ats.iot.$($region).amazonaws.com"
	    Write-LogMessage -Type Verbose -Msg "Runing DPA-IOT"
	    return Test-NetConnectivity -ComputerName $AwsIOTAddress -Port 443
    }
	Else
	{
        # In case $region is empty, we override the entire test and return our own customObject result.
		Write-LogMessage -Type Info -Msg "Skipping test since host name is empty (Previous check probably failed)"
		$errorMsg = "Skipping test since host name is empty (DPA-Assets failed?)"
        $result = $false
        return [PsCustomObject]@{
		expected = $true;
		actual = $false;
		errorMsg = $errorMsg;
		result = $result;
	    }
	}
}

function DPA-IOTCert {
    [OutputType([PsCustomObject])]
    param ()
    
    $expected = "CN=Amazon RSA 2048 M01, O=Amazon, C=US"
    $result = $false
    $errorMsg = ""
    $actual = ""

    Write-LogMessage -Type Verbose -Msg "Starting DPA-IOTCert..."
    
    if (![string]::IsNullOrEmpty($Region)) {
        try {
            $CertURL = "https://a2m4b3cupk8nzj-ats.iot.$($Region).amazonaws.com:443"
            $cert = Get-SSLCertificateDetails -Url $CertURL
            $actual = $cert.Issuer
            
            if ($actual -ne $expected) {
                $errorMsg = "The expected certificate ('$($expected)') doesn't match the actual certificate received ('$($actual)'). Test it by browsing to this URL: '$($CertURL)'."
            } else {
                $result = $true
            }

            Write-LogMessage -Type Verbose -Msg "Finished DPA-IOTCert..."
        } catch {
            $errorMsg = "$(Collect-ExceptionMessage) $($errMsg)"
        }
    } else {
        $errorMsg = "Skipping test since host name is empty (DPA-Assets failed?)"
    }
    
    return [PsCustomObject]@{
        expected = $expected;
        actual = $actual;
        errorMsg = $errorMsg;
        result = $result;
    }
}

function CheckEndpointProtectionServices() {
    $expected = "Stopped"
    $errorMsg = ""
    $actual = ""
    $result = $true

    Write-LogMessage -Type Verbose -Msg "Starting CheckEndpointProtectionServices..."

    $endpointProtectionServices = @(
        "*AVGNT*",
        "*Avast*", 
        "*Avira*", 
        "*Bitdefender*", 
        "*Carbon Black*",
        "*Check Point*", 
        "*Cisco*", 
        "*Comodo*", 
        "*Cortex*", 
        "*CrowdStrike*",
        "*CylancePROTECT*", 
        "*ESET Endpoint*", 
        "*FireEye*", 
        "*Guardicore*",
        "*Fortinet*", 
        "*Kaspersky*", 
        "*Malwarebytes*", 
        "*McAfee*", 
        "*Microsoft Defender*",
        "*Palo Alto*", 
        "*Panda*", 
        "*Qualys*", 
        "*SentinelOne*", 
        "*Sophos*",
        "*Symantec*", 
        "*Trend Micro*", 
        "*Webroot*"
    )

    try {
        $allservices = Get-WmiObject win32_service -ErrorAction SilentlyContinue
        foreach ($servicePattern in $endpointProtectionServices) {
            $serviceStatus = $allservices | Where-Object {
                $_.Description -like $servicePattern -or
                $_.DisplayName -like $servicePattern -or
                $_.Name -like $servicePattern
            }

            foreach ($svc in $serviceStatus) {
                if ($svc -and $svc.State -eq "Running") {
                    $errorMsg += "Detected running AV/ATP Service: '$($svc.DisplayName)'`n"
                    $actual = "Running"
                    $result = $false
                } elseif ($svc -and $svc.State -eq "Stopped") {
                    # If service is found but stopped, set actual to "Stopped" only if no running services are detected
                    if ($result) {
                        $actual = "Stopped"
                    }
                }
            }
        }

        # Append advisory message if any AV/ATP services are running
        if ($errorMsg) {
            $errorMsg += "Note: It's advised to disable AV/ATP agents during installation or upgrades. Refer to: https://docs.cyberark.com/ispss-deployment/latest/en/Content/Privilege%20Cloud/PrivCloud-install-antivirus.htm"
        }

        Write-LogMessage -Type Verbose -Msg "Finished CheckEndpointProtectionServices..."
    }
    catch {
        $errorMsg = "Could not check CheckEndpointProtectionServices. Error: $(Collect-ExceptionMessage $_.Exception)"
    }

    return [PsCustomObject]@{
        Expected = $expected
        Actual = $actual
        ErrorMsg = $errorMsg
        Result = $result
    }
}


# @FUNCTION@ ======================================================================================================================
# Name...........: CheckNoProxy
# Description....: Checks proxy configuration, required direct access for RDS deployment
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function CheckNoProxy()
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting CheckNoProxy..."
		$actual = ""
		$result = $False
		$errorMsg = ""
        $expected = $false

		$proxyStatus = (netsh winhttp show proxy)
		
        
        #Check if machine name is over 15 chars.
        if($proxyStatus -match "Direct access"){
            $result = $true
		    $errorMsg = ""
            $actual = $false
        }
        Else{
            $result = $false
		    $errorMsg = "Please disable proxy for the duration of the installation. run `"netsh winhttp show proxy`""
			$actual = $true
        }
		
		Write-LogMessage -Type Verbose -Msg "Finished CheckNoProxy"
	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $false;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: CheckNoProxyRDS
# Description....: Checks proxy configuration, requires direct access for RDS deployment
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
Function CheckNoProxyRDS()
{
	Write-LogMessage -Type info	-Msg "Checking if machine has proxy configuration..." -early
	if(-not($(netsh winhttp show proxy)) -match "Direct access")
	{
		Write-LogMessage -Type Warning -Msg "Proxy configuration detected, please disable and rerun script (you can re-enable after RDS is complete). Run `"netsh winhttp show proxy`" to see current config, to disable run `"netsh winhttp reset proxy`""
		Pause
		Exit
	}
	Else
	{
		Write-LogMessage -Type info	-Msg "No proxy configured." -early
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: remoteAppDomainUserPermissions
# Description....: Checks that executing user is in "Domain Users" group in AD and in local "administrators" group in PSM machine.
# Parameters.....: None
# Return Values..: True False
# =================================================================================================================================
Function remoteAppDomainUserPermissions()
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting remoteAppDomainUserPermissions..."
		$actual = ""
		$result = $False
		$errorMsg = ""
        $expected = $true

        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
		$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)

		if(($WindowsPrincipal.IsInRole("Domain Users") -eq $False) -or 
    	($WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $False))
		{
			# NOT domain user with administrative rights
			$actual = $false
			$result = $False
			$errorMsg = "Installing windows user must be a member of `"Domain Users`" group and in the local administrators group (requires logout login to take affect). If the user is from a different domain, this error will not go away, but as a workaround, after PSM is installed, perform the actions described here: https://cyberark.my.site.com/s/article/Publish-PSMInitSession-as-a-RemoteApp-Program"
			$expected = $true
		}
		Else{
			$actual = $true
			$result = $true
			$errorMsg = ""
			$expected = $true
		}
   
		Write-LogMessage -Type Verbose -Msg "Finished remoteAppDomainUserPermissions"

	} catch {
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception) Installing windows user must be a member of `"Domain Users`" group and in the local administrators group (requires logout login to take affect). If the user is from a different domain, this error will not go away, but as a workaround, after PSM is installed, perform the actions described here: https://cyberark.my.site.com/s/article/Publish-PSMInitSession-as-a-RemoteApp-Program"
	}

	return [PsCustomObject]@{
		actual = $actual;
		result = $result;
		errorMsg = $errorMsg;
		expected = $true;
	}
}

Function remoteAppDomainUserPermissionsRDS()
{
	# if script was ran with outofdomain flag we need to skip this test.
	if(-not ($OutOfDomain)){
		Write-LogMessage -Type Info -Msg "Checking current windows user has permissions to configure remoteApp..." -Early
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
		$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
		$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)

		if(($WindowsPrincipal.IsInRole("Domain Users") -eq $False) -or 
    	($WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $False))
		{
			# NOT domain user with administrative rights
			Write-LogMessage -type Error -MSG "Installing windows user must be a member of `"Domain Users`" group and in the local administrators group (requires logout login to take affect). If the user is from a different domain, this error will not go away, but as a workaround, after PSM is installed, perform the actions described here: https://cyberark.my.site.com/s/article/Publish-PSMInitSession-as-a-RemoteApp-Program"
            Write-LogMessage -type Warning -MSG "We will proceed with install, but remember to fix this issue after PSM component is successfully installed if you want to enjoy RemoteApp features."
			Pause
		}
	}
}

function GetOSVersionInternal()
{
Set-Variable OS_VERSION_WINDOWS_2008_R2_PCKG -value 0 -scope script
Set-Variable OS_VERSION_WINDOWS_2012_R2_PCKG -value 1 -scope script
Set-Variable OS_VERSION_WINDOWS_2016_PCKG -value 2 -scope script
Set-Variable OS_VERSION_WINDOWS_2019_PCKG -value 3 -scope script
Set-Variable OS_VERSION_UNKNOWN_PCKG -value -1 -scope script
Set-Variable UNKNOWN_ERROR_PCKG -value -2

	$ReturnCode = $UNKNOWN_ERROR_PCKG;
	
	trap 
	{ 
		exit $UNKNOWN_ERROR_PCKG
	};

	if(([Environment]::OSVersion.Version -ge (new-object 'Version' 10,0,17763)) -eq $True)
	{
		$ReturnCode = $OS_VERSION_WINDOWS_2019_PCKG;
	}
	elseif(([Environment]::OSVersion.Version -ge (new-object 'Version' 10,0)) -eq $True)
	{
		$ReturnCode = $OS_VERSION_WINDOWS_2016_PCKG;
	}
	else 
	{ 
		$ReturnCode = $OS_VERSION_UNKNOWN_PCKG;
	};
	
	return $ReturnCode
}

function NewSessionDeployment([string]$ConnectionBroker, [string]$SessionHost)
{
    New-RDSessionDeployment -ConnectionBroker ("$ConnectionBroker") -SessionHost ("$SessionHost") -WarningAction SilentlyContinue -errorAction SilentlyContinue
}

function NewSessionCollection([string]$CollectionName, [string]$SessionHost, [string]$ConnectionBroker)
{
    Write-LogMessage -type Info -MSG "Creating RDS collection called $CollectionName" -Early
    New-RDSessionCollection -CollectionName $CollectionName -SessionHost ("$SessionHost") -ConnectionBroker ("$ConnectionBroker") -WarningAction SilentlyContinue -errorAction SilentlyContinue
}

function IsLoginWithDomainUser()
{
       Add-Type -AssemblyName System.DirectoryServices.AccountManagement
	   $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
	   
	   if($UserPrincipal.ContextType -eq "Domain") 
	   {
			return $true
	   }
	   else
	   {
			return $false
	   } 	
}


function RemoveValueFromRegistry([string]$key, [string]$name)
{
    Write-LogMessage -Type Info -Msg "Removing the registry value '$key$name'" -Early
	Try 
	{
		# if registry path does not exists, there is no need to remove it.
		if((Test-Path $key))
		{
			if (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue)
			{
				Remove-ItemProperty -Path $key -Name $name -ErrorAction Stop
				
				#Verify that the value no longer exists
				if (Get-ItemProperty -Path $key -Name $name -ErrorAction SilentlyContinue)
				{
                    Write-LogMessage -Type Error -Msg "'Remove-ItemProperty' command failed to remove the '$key$name' registry key"
                    return $false
				}
                Write-LogMessage -Type Success -Msg "Successfully removed registry value '$key$name'."
                return $true
			}
		}
	}
	Catch 
	{
        Write-LogMessage -Type error -Msg "Failed to remove registry key: '$key$name'"
        return $false
	}
	 Write-LogMessage -Type Info -Msg "Registry value '$key$name' does not exist" -Early
}

function Add-CAUserRight{
    [CmdletBinding()] 
	param(
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$userName,
   [parameter(Mandatory=$true)]
   [ValidateNotNullOrEmpty()]$userRight
    )
    	Process {
        Try{
            Write-LogMessage -type info -MSG "Start adding ""$userRight"" user rights to user $userName" -Early
            Try {
                $ntprincipal = new-object System.Security.Principal.NTAccount "$userName"
                $userSid = $ntprincipal.Translate([System.Security.Principal.SecurityIdentifier])
                $userSidstr = $userSid.Value.ToString()
            } Catch {
                $userSidstr = $null
            }
            
            if( [string]::IsNullOrEmpty($userSidstr) ) {
                Write-LogMessage -type info -MSG "User $userName not found!" "Error"
                return $false
            }

            Write-LogMessage -type info -MSG "User SID: $($userSidstr)" -Early

            $tempPath = [System.IO.Path]::GetTempPath()
            $importPath = Join-Path -Path $tempPath -ChildPath "import.inf"
            if(Test-Path $importPath) { Remove-Item -Path $importPath -Force }
            $exportPath = Join-Path -Path $tempPath -ChildPath "export.inf"
            if(Test-Path $exportPath) { Remove-Item -Path $exportPath -Force }
            $secedtPath = Join-Path -Path $tempPath -ChildPath "secedt.sdb"
            if(Test-Path $secedtPath) { Remove-Item -Path $secedtPath -Force }
  
            Write-LogMessage -type info -MSG "Export current Local Security Policy to file $exportPath" -Early
            secedit.exe /export /cfg "$exportPath" > $null

            #if $userRight does not exist - add it 
            $val = Select-String $exportPath -Pattern "$userRight"
            if ($null -eq $val)
            {
$importFileContentTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$userRight = $userName
"@

                Write-LogMessage -type info -MSG "Import new settings to Local Security Policy from file $importPath" -Early
                $importFileContentTemplate | Set-Content -Path $importPath -Encoding Unicode -Force > $null

                secedit.exe /configure /db "$secedtPath" /cfg "$importPath" /areas USER_RIGHTS > $null
                      
                Remove-Item -Path $importPath -Force
                Remove-Item -Path $exportPath -Force
                Remove-Item -Path $secedtPath -Force

                Write-LogMessage -type info -MSG "Finished adding ""$userRight"" user rights to user $userName"
                return $true
            }
            else
            {
	            $currentRightKeyValue = (Select-String $exportPath -Pattern "$userRight").Line

	            $splitedKeyValue = $currentRightKeyValue.split("=",[System.StringSplitOptions]::RemoveEmptyEntries)
                $currentSidsValue  = $splitedKeyValue[1].Trim()

	            $newSidsValue = ""
						
	            if( $currentSidsValue -notlike "*$($userSidstr)*" ) {
		            Write-LogMessage -type info -MSG "Modify ""$userRight"" settings" -Early
			
		            if( [string]::IsNullOrEmpty($currentSidsValue) ) {
			            $newSidsValue = "*$($userSidstr)"
		            } else {
			            $newSidsValue = "*$($userSidstr),$($currentSidsValue)"
		            }
		
$importFileContentTemplate = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
$userRight = $newSidsValue
"@

                    Write-LogMessage -type info -MSG "Import new settings to Local Security Policy from file $importPath" -Early
                    $importFileContentTemplate | Set-Content -Path $importPath -Encoding Unicode -Force > $null

                    secedit.exe /configure /db "$secedtPath" /cfg "$importPath" /areas USER_RIGHTS > $null

	                } else {
		                Write-LogMessage -type info -MSG "NO ACTIONS REQUIRED! User $userName already in ""$userRight""" -Early
	                }
                      
                    if(Test-Path $importPath) { Remove-Item -Path $importPath -Force }
                    if(Test-Path $exportPath) { Remove-Item -Path $exportPath -Force }
                    if(Test-Path $secedtPath) { Remove-Item -Path $secedtPath -Force }

	                Write-LogMessage -type info -MSG "Finished adding ""$userRight"" user rights to user $userName" -Early
	                return $true
               }
			
		}Catch{
         Write-LogMessage -type Error -MSG "Failed to add  ""$userRight"" user right for user $userName." "Error $_.Exception.Message"
		}
      return $false
	}
	End{
   }
}


function AddNetworkLogonRight()
{
	$addUserRight = Add-CAUserRight "NETWORK SERVICE" "SeNetworkLogonRight"
	if ($addUserRight -eq $false)
	{
		throw "Failed to add netwotk logon right for to NETWORK SERVICE user. Connection Broker will not be installed."
	}
}

function Get-SSLCertificateDetails {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Url
    )
    
    $tcp = $null
    $sslStream = $null
    
    try {
        $uri = [System.Uri]::new($Url)
        $tcp = New-Object System.Net.Sockets.TcpClient
        try {
            $tcp.Connect($uri.Host, $uri.Port)
        } catch {
            $originalErrorMsg = "Could not connect to $($uri.Host):$($uri.Port) Error: $($_.Exception.Message)"
            Throw $originalErrorMsg
        }
        
        $stream = $tcp.GetStream()
        $sslStream = New-Object System.Net.Security.SslStream -ArgumentList $stream
    try {
        $sslStream.AuthenticateAsClient($uri.Host, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    } catch {
        $originalErrorMsg = "Failed to authenticate as client to $($uri.Host) Error: $($_.Exception.Message)"
    Throw $originalErrorMsg
    }
        
        $certificate = $sslStream.RemoteCertificate
        if ($null -eq $certificate) { throw "Failed to get the remote certificate from the SslStream" }
        
        return $certificate
    } catch {
        $script:errMsg = "Error occurred while fetching CERT: $originalErrorMsg"
        throw $errMsg
    } finally {
        $sslStream.Close()
        $tcp.Close()
    }
}

Function enforceTLS {
    # Check the current SecurityProtocol setting
    $securityProtocol = [Net.ServicePointManager]::SecurityProtocol
	if ($securityProtocol -ne 'SystemDefault' -and $securityProtocol -notmatch 'Tls12') {
        Write-LogMessage -type Info -MSG "Detected SecurityProtocol not highest settings ('$($securityProtocol)'), enforcing TLS 1.2."
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	}
        # Registry checks for .NET Framework strong cryptography settings
        $GetTLSReg86 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        $GetTLSReg64 = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name "SchUseStrongCrypto" -ErrorAction SilentlyContinue
        
        # Registry checks for TLS 1.2 being explicitly disabled in Client and Server
        $Gettls12ClientValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -ErrorAction SilentlyContinue
        $Gettls12ServerValue = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -ErrorAction SilentlyContinue

        $gettls12ClientDefaultDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -ErrorAction SilentlyContinue
        $gettls12ServerDefaultDisabled = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -ErrorAction SilentlyContinue

        $TLSReg86 = $GetTLSReg86 -ne $null -and $GetTLSReg86.SchUseStrongCrypto -eq 0
        $TLSReg64 = $GetTLSReg64 -ne $null -and $GetTLSReg64.SchUseStrongCrypto -eq 0
        $tls12ClientValue = $Gettls12ClientValue -ne $null -and $Gettls12ClientValue.Enabled -eq 0
        $tls12ServerValue = $Gettls12ServerValue -ne $null -and $Gettls12ServerValue.Enabled -eq 0
        $tls12ClientDefaultDisabled = $gettls12ClientDefaultDisabled -ne $null -and $gettls12ClientDefaultDisabled.DisabledByDefault -eq 1
        $tls12ServerDefaultDisabled = $gettls12ServerDefaultDisabled -ne $null -and $gettls12ServerDefaultDisabled.DisabledByDefault -eq 1

        if ($TLSReg86 -or $TLSReg64 -or $tls12ClientValue -or $tls12ServerValue -or $tls12ClientDefaultDisabled -or $tls12ServerDefaultDisabled) {
            Write-LogMessage -Type Info -MSG "Adjusting settings to ensure TLS 1.2 is not explicitly disabled and strong cryptography is enforced."
            if ($TLSReg86) {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -Verbose
            }
            if ($TLSReg64) {
                Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ClientValue) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "Enabled" -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ServerValue) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "Enabled" -Value 1 -Type DWord -Force -Verbose
            }
            if ($tls12ClientDefaultDisabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name "DisabledByDefault" -Value 0 -Type DWord -Force -Verbose
            }
            if ($tls12ServerDefaultDisabled) {
                Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name "DisabledByDefault" -Value 0 -Type DWord -Force -Verbose
            }

            Write-LogMessage -Type Warning -MSG "Settings adjusted. Please RESTART the system for the changes to take effect."
            Write-LogMessage -Type Warning -MSG "If this check keeps looping, you can skip it with -skipTLS flag when running the script."
            Pause
            Exit
        } else {
            Write-LogMessage -Type Info -MSG "TLS 1.2 is properly configured." -Early
        }
}

# can be removed later versions
import-module RemoteDesktop -Verbose:$false | Out-Null;


# @FUNCTION@ ======================================================================================================================
# Name...........: InstallRDS
# Description....: Installs RDS role on the machine.
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
function InstallRDS{
$script:TerminalServicesKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
$script:RedirectClipboardValue = "fDisableClip"
$script:RedirectDrivesValue	= "fDisableCdm"

    # Get the details of the Remote Desktop Services rule
    Write-LogMessage -Type Info -Msg "Deploying RDS Roles" -Early
	
	# Check if machine has pending restarts.
	PendingRestartRDS
	
	# Check machine has no proxy configuration
	CheckNoProxyRDS

	# Check user is in Domain Users and Administrators group to configure remoteapp
	remoteAppDomainUserPermissionsRDS
	
	if($gpoRDSerrorsfound -gt 0){
		Write-LogMessage -type Warning -MSG "Please fix GPO RDS related errors first."
		Return
	}
	
    try {
		$RDSFeature = Get-WindowsFeature *Remote-Desktop-Services*

		# Check if the RDS rule is not installed
		    if ($RDSFeature.Installed -eq $false)
		    {
                $AdminUserName = whoami
                Write-LogMessage -type Info -MSG "Logged in User is: $AdminUserName" -Early
                
		    	Write-LogMessage -type Info -MSG "Installing Microsoft Remote Desktop Services, this may take a few minutes..." -Early
		    	# Install the RD-Session Host (ignore the warning that is prompt to the user by microsoft to restart the machine)
		    	add-windowsfeature Remote-Desktop-Services,RDS-RD-Server -WarningAction SilentlyContinue

                # Set Schedule Task to Disable NLA
                SetScheduledTask -taskName $taskNameNLA -TriggerType $TriggerAtStart -taskDescription $taskDescrNLA -action $actionNLA -AdminUsername SYSTEM

                # Set Schedule Task to resume RDS install after user logs back in
				if($OutOfDomain)
				{
					# if script was ran with out of domain flag, we make sure to resume out of domain checks after restart
					SetScheduledTask -taskName $taskNameRDS -TriggerType $TriggerAtLogon -taskDescription $taskDescrRDS -action $ActionRDSoutOfDomain -AdminUsername $AdminUserName
				}
				Else
				{
					SetScheduledTask -taskName $taskNameRDS -TriggerType $TriggerAtLogon -taskDescription $taskDescrRDS -action $actionRDS -AdminUsername $AdminUserName
				}
                
				
				# Skip CPMConnectionTest since we're about to perform restart anyway.
				$script:CPMConnectionTestSkip = $true
		    	Write-LogMessage -type Warning -MSG "The server will restart to apply Microsoft Remote Desktop Services, press ENTER to continue."
		    	Pause
                Restart-Computer -Force
		    }
            Else # If the Remote Desktop Rule is installed , we make sure the connection broker is also installed (such scenario will happen after we restart the machine)
            {
                UnsetScheduledTask -taskName $taskNameRDS

                Write-LogMessage -type info -MSG "Remote-Desktop-Services (RD Session Host) is already installed on the machine. Checking if RDS-Connection-Broker is installed" -Early
                # Checks to see if the executing account is a domain member/user which is a pre-requisite for Connection Broker
			    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
			    $PrincipalObject = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
			    if (-not (IsLoginWithDomainUser))
			    {
					# if the computer is in a domain and the user is local, display relevant message
					if ((Get-CimInstance -Class Win32_ComputerSystem).PartOfDomain)
					{
						Write-LogMessage -type Warning -MSG "Machine is in domain but you are logged in with a local user, login with a domain user and rerun the script to complete RDS CB Install."
						Pause
						return
					}
				# Machine is not part of domain and user is not domain user.
                Write-LogMessage -type Warning -MSG "Machine is not part of any domain, RDS CB will not be installed (PSM remoteApp feature will not work)."
				Write-LogMessage -type Warning -MSG "You can ignore this error if machine is intended to be out of domain installation."
				Pause
				return
			    }
                # add network logon rights, used in case its missing or if CPM was installed first and hardened the machine.
                AddNetworkLogonRight

			    # Get the details of the Connection Broker rule
			    $ConnectionBrokerFeature = Get-WindowsFeature *RDS-Connection-Broker*

                # Restart if Broker state is pending restart
                if ($ConnectionBrokerFeature.installState -eq "UninstallPending")
                {
                    
                    $ConnectionBrokerFeature
                    Write-LogMessage -type Warning -MSG "`n 1. We detected Connection Broker was recently uninstalled, to complete operation, you must restart first."
                    Write-LogMessage -type Warning -MSG " 2. Script will automatically resume after restart, press ENTER to continue."
                    # Set Schedule Task to resume RDS install after user logs back in
                    $AdminUserName = whoami
					if($OutOfDomain)
					{
						# if script was ran with out of domain flag, we make sure to resume out of domain checks after restart
						SetScheduledTask -taskName $taskNameRDS -TriggerType $TriggerAtLogon -taskDescription $taskDescrRDS -action $ActionRDSoutOfDomain -AdminUsername $AdminUserName
					}
					Else
					{
						SetScheduledTask -taskName $taskNameRDS -TriggerType $TriggerAtLogon -taskDescription $taskDescrRDS -action $actionRDS -AdminUsername $AdminUserName
					}
					# Skip CPMConnectionTest since we're about to perform restart anyway.
					$script:CPMConnectionTestSkip = $true
                    pause
                    Restart-Computer -Force
                }

                    # Check if logged in user domain matches the machine domain, in cases where Primary DNS suffix is set, it will be different.
                    if($(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tcpip\Parameters | select -ExpandProperty Domain) -eq $env:userdnsdomain)
                    {
                        $cb="$env:computername.$env:userdnsdomain"
                    }
                    Else
                    {
                        $cb="$env:computername.$(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tcpip\Parameters | select -ExpandProperty Domain)"
                    }

			    # Check if the Connection broker rule is not installed
			    if ($ConnectionBrokerFeature.Installed -eq $false)
                {
                    try
                    {
                        # Make sure Redirect Drives and Clipboard is not configured which is mandatory for Connection Broker installation
                        RemoveValueFromRegistry $TerminalServicesKey $RedirectClipboardValue
                        RemoveValueFromRegistry $TerminalServicesKey $RedirectDrivesValue
                        
                        Write-LogMessage -type info -MSG "Installing RDS-Connection-Broker role" -Early

                        # Installing Remote Desktop Broker - Session Host
                        NewSessionDeployment ($cb) ($cb)
                        
                        # Configure the RDS Collection - remoteapp
                        NewSessionCollection ($CollectionName) ($cb) ($cb)

                        #disable NLA just in case it comes back.
                        Disable-NLA

                        $ConnectionBrokerFeature = Get-WindowsFeature *RDS-Connection-Broker*

                        if($ConnectionBrokerFeature.Installed -eq $true){
                            Write-LogMessage -type Success -MSG "RDS Connection Broker was installed successfully"
                        }
                        Else{
                            Write-LogMessage -type Error -MSG "Failed to install RDS Connection-Broker role, fix errors and rerun script."
                        }
                    }
			        catch
			        {
					    Write-LogMessage -type Error -MSG "Failed to install RDS Connection-Broker role, fix errors and rerun script."
			        }
                }
			    else
                    {
                    # check if the collection is configured
                    $PSMcollection = Get-RDSessionCollection -CollectionName $CollectionName
                    if($PSMcollection){
                        Write-LogMessage -type info -MSG "RDS Collection '$($CollectionName)' already exists. No changes will be applied." -Early
                    }Else{
                        Write-LogMessage -type Warning -MSG "RDS Collection '$($CollectionName)' not found. Configuring the collection now." -Early
                        # Configure the RDS Collection - remoteapp
                        NewSessionCollection ($CollectionName) ($cb) ($cb)
                    }

				    # Get the details of the Windows Internal Database rule
				    $WindowsInternalDatabaseFeature = Get-WindowsFeature *Windows-Internal-Database*

				    # Check if Windows Internal Database is installed as it is required for the Connection Broker to work properly
				    if ($WindowsInternalDatabaseFeature.Installed -eq $false)
				    {
					    throw "Failed to validate Connection Broker installation.The mandatory Windows Internal Database feature is not installed." 
				    }
				    else
				    {
					    Write-LogMessage -type info -MSG "RDS-Connection-Broker is already installed on the machine. No changes will be applied" -Early
				    }
			    }
		    }
        }
        catch
        {
            $ExceptionMsg = "Failed to install RDS rules. Error: " + ($_.Exception).Message
            Write-LogMessage -type Error "$($ExceptionMsg)"
        }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: SetScheduledTask
# Description....: Add Schedule Task that runs after restart
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
function SetScheduledTask {
    [CmdletBinding()]
	param(
		$AdminUsername,
        $TriggerType,
        $taskName,
        $action,
        $taskDescription
	)
    Process {
        Write-LogMessage -type Info -MSG "Creating scheduled task: $taskName" -Early

        # Check if scheduled task doesn't exists. If it doesn't, creating it.
        $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }

        if(!$taskExists) {            
            $params = @{
                "TaskName"    = $taskName
                "Action"      = $action
                "Trigger"     = $TriggerType
                "User"        = "$AdminUsername"
                "RunLevel"    = "Highest"
                "Description" = "$taskDescription"
            }
            $null = Register-ScheduledTask @params
        } else {
            
        }
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: UnsetScheduledTask
# Description....: Removes a Scheduled Task
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
function UnsetScheduledTask {
    [CmdletBinding()]
	param(
		$taskName
	)
    Process {
        # Check if scheduled task doesn't exists. If it doesn't, creating it.
        $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }

        # Check if scheduled task exists. If it is, deleting it.
        if($taskExists) {
            $null = Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
    }
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Disable-NLA
# Description....: Disables NLA
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
function Disable-NLA()
{
    # Disable NLA
    Write-LogMessage -type Info -MSG "Disabling NLA..." -Early
    $disableNLA = get-CimInstance "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter 'TerminalName = "RDP-Tcp"' | Invoke-CimMethod -MethodName SetUserAuthenticationRequired -Arguments @{UserAuthenticationRequired = 0}

    # Remove scheduled Task so we don't run it infinitely.
    UnsetScheduledTask -taskName $taskNameNLA
}

# @FUNCTION@ ======================================================================================================================
# Name...........: PromptForRDSInstall
# Description....: Prompt user for RDS install
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
function PromptForRDSInstall()
{
    $decisionPSM = Get-Choice -Title "Deploy RDS? (Required for Privileged Session Management)" -Options "Yes (Recommended)", "No" -DefaultChoice 1
    if ($decisionPSM -eq "Yes (Recommended)")
    {
        Write-LogMessage -type Info -MSG "Selected YES to install RDS." -Early
        InstallRDS
    }
    Else
    {
        Write-LogMessage -type Info -MSG "Selected NOT to install RDS, skipping RDS role install..." -Early
    }
}

# @FUNCTION@ ======================================================================================================================
# Name...........: checkIfPSMisRequired
# Description....: Check if PSM will be installed on the machine, depending on answer, we will deploy RDS role.
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
function checkIfPSMisRequired()
{
    # Check if RDS/CB installed, 
    $RDSFeature = Get-WindowsFeature *Remote-Desktop-Services*
    $ConnectionBrokerFeature = Get-WindowsFeature *RDS-Connection-Broker*
    $PSMcollection = Get-RDSessionCollection -CollectionName $CollectionName -ErrorAction SilentlyContinue


    if ($OutOfDomain -eq $true)
    {
        if ($RDSFeature.Installed -eq $false)
        {
            PromptForRDSInstall
        }
    }
    else
    {
        if (($RDSFeature.Installed -eq $false) -or ($ConnectionBrokerFeature.Installed -eq $false) -or ($PSMcollection -eq $null))
        {
            PromptForRDSInstall
        }
    }
}

<#
Function CheckPrerequisites {
    Param (
        [String[]]$selectedComponents
    )
    
    Try {
        $global:table = @()
        $errorCnt = 0
        $warnCnt = 0
        $table = ""

        # Track executed methods
        $executedMethods = @{}

        # If "All" is selected, include all components dynamically
        if ($selectedComponents -contains "All") {
            $selectedComponents = $componentMapping.Keys
        }

        # General checks
        Write-LogMessage -Type Warning -Msg "< General Related Checks >"
        foreach ($method in $arrCheckPrerequisitesGeneral) {
            if (-not $executedMethods[$method]) {
                Try {
                    Write-Progress -Activity "Checking $method..."
                    $resultObject = &$method

                    if ($null -eq $resultObject -or !$resultObject.result) {
                        $errorCnt++
                    }

                    Write-Progress -Activity "$method completed" -Completed
                }
                Catch {
                    $resultObject.errorMsg = $_.Exception.Message
                    $errorCnt++
                }

                if ($resultObject.errorMsg -ne $g_SKIP) {
                    AddLineToReport $method $resultObject
                } else {
                    $resultObject.errorMsg = ""
                }

                AddLineToTable $method $resultObject
                $executedMethods[$method] = $true
            }
        }

        # Specific checks
        foreach ($component in $selectedComponents) {
            $arrToCheck = $componentMapping[$component]
            
            if ($arrToCheck -ne $null) {
                Write-LogMessage -Type Warning -Msg "< $component Related Checks >"
                
                foreach ($method in $arrToCheck) {
                    if (-not $executedMethods[$method]) {
                        Try {
                            Write-Progress -Activity "Checking $method..."
                            $resultObject = &$method  

                            if ($null -eq $resultObject -or !$resultObject.result) {
                                $errorCnt++
                            }

                            Write-Progress -Activity "$method completed" -Completed
                        }
                        Catch {
                            $resultObject.errorMsg = $_.Exception.Message
                            $errorCnt++
                        }

                        if ($resultObject.errorMsg -ne $g_SKIP) {
                            AddLineToReport $method $resultObject
                        } else {
                            $resultObject.errorMsg = ""
                        }

                        AddLineToTable $method $resultObject
                        $executedMethods[$method] = $true
                    }
                }
            }
        }

        # Final logging of errors and warnings
        if ($global:table.Count -gt 0) {
            $warnCnt = $global:table.Count - $errorCnt
            Write-LogMessage -Type Info -Msg "Checking Prerequisites completed with $errorCnt failures and $warnCnt warnings."
            Write-LogMessage -Type Info -Msg "$SEPARATE_LINE"
            $global:table | Format-Table -Wrap
            Write-LogMessage -Type LogOnly -Msg $($global:table | Out-String)
        } else {
            Write-LogMessage -Type Success -Msg "Checking Prerequisites completed successfully"
        }
    }
    Catch {
        Throw $(New-Object System.Exception("CheckPrerequisites: Failed to run CheckPrerequisites", $_.Exception))
    }
}
#>

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-Choice
# Description....: Prompts user for Selection choice
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function Get-Choice{
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]
        $Options,

        [Parameter(Position = 2)]
        $DefaultChoice = -1
    )
    if ($DefaultChoice -ne -1 -and ($DefaultChoice -gt $Options.Count -or $DefaultChoice -lt 1))
    {
        Write-Warning "DefaultChoice needs to be a value between 1 and $($Options.Count) or -1 (for none)"
        exit
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = ""
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen
    #calculate width required based on longest option text and form title
    $minFormWidth = 300
    $formHeight = 44
    $minButtonWidth = 150
    $buttonHeight = 23
    $buttonY = 12
    $spacing = 10
    $buttonWidth = [Windows.Forms.TextRenderer]::MeasureText((($Options | Sort-Object Length)[-1]), $form.Font).Width + 1
    $buttonWidth = [Math]::Max($minButtonWidth, $buttonWidth)
    $formWidth = [Windows.Forms.TextRenderer]::MeasureText($Title, $form.Font).Width
    $spaceWidth = ($options.Count + 1) * $spacing
    $formWidth = ($formWidth, $minFormWidth, ($buttonWidth * $Options.Count + $spaceWidth) | Measure-Object -Maximum).Maximum
    $form.ClientSize = New-Object System.Drawing.Size($formWidth, $formHeight)
    $index = 0
    #create the buttons dynamically based on the options
    foreach ($option in $Options)
    {
        Set-Variable "button$index" -Value (New-Object System.Windows.Forms.Button)
        $temp = Get-Variable "button$index" -ValueOnly
        $temp.Size = New-Object System.Drawing.Size($buttonWidth, $buttonHeight)
        $temp.UseVisualStyleBackColor = $True
        $temp.Text = $option
        $buttonX = ($index + 1) * $spacing + $index * $buttonWidth
        $temp.Add_Click({ 
                $script:result = $this.Text; 
                $form.Close() 
            })
        $temp.Location = New-Object System.Drawing.Point($buttonX, $buttonY)
        $form.Controls.Add($temp)
        $index++
    }
    $shownString = '$this.Activate();'
    if ($DefaultChoice -ne -1)
    {
        $shownString += '(Get-Variable "button$($DefaultChoice-1)" -ValueOnly).Focus()'
    }
    $shownSB = [ScriptBlock]::Create($shownString)
    $form.Add_Shown($shownSB)
    [void]$form.ShowDialog()
    return $result
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Get-MultipleChoice
# Description....: Prompts user for Selection choice (supports multiple selections, with "All" selection functionality)
# Parameters.....: None
# Return Values..: 
# =================================================================================================================================
Function Get-MultipleChoice {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        $Title,

        [Parameter(Mandatory = $true, Position = 1)]
        [String[]]$Options,

        [Parameter(Position = 2)]
        $DefaultChoice = @()
    )

    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
    [System.Windows.Forms.Application]::EnableVisualStyles()
    $script:result = @()
    $form = New-Object System.Windows.Forms.Form
    $form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::FixedDialog
    $form.BackColor = [Drawing.Color]::White
    $form.TopMost = $True
    $form.Text = $Title
    $form.ControlBox = $False
    $form.StartPosition = [Windows.Forms.FormStartPosition]::CenterScreen

    # Set form size
    $minFormWidth = 400
    $formHeight = 100 + ($Options.Count * 30)
    $form.ClientSize = New-Object System.Drawing.Size($minFormWidth, $formHeight)

    $checkboxes = @{ }
    $eventHandlingEnabled = $true

    Function Toggle-AllCheckboxes {
        param($state)
        $eventHandlingEnabled = $false
        foreach ($key in $checkboxes.Keys) {
            if ($key -ne "All") {
                $checkboxes[$key].Checked = $state
            }
        }
        $eventHandlingEnabled = $true
    }

    Function Check-AllState {
        if ($eventHandlingEnabled) {
            $allChecked = $true
            foreach ($key in $checkboxes.Keys) {
                if ($key -ne "All" -and !$checkboxes[$key].Checked) {
                    $allChecked = $false
                    break
                }
            }
            $eventHandlingEnabled = $false
            $checkboxes["All"].Checked = $allChecked
            $eventHandlingEnabled = $true
        }
    }

    # Create CheckBoxes for every option
    $index = 0
    foreach ($option in $Options) {
        $checkbox = New-Object System.Windows.Forms.CheckBox
        $checkbox.Text = $option
        $checkbox.Location = New-Object System.Drawing.Point(20, (20 + ($index * 30)))
        $checkbox.Size = New-Object System.Drawing.Size(350, 30)

        $checkboxes[$option] = $checkbox

        if ($option -eq "All") {
            $checkbox.Add_CheckedChanged({
                if ($eventHandlingEnabled) {
                    if ($checkboxes["All"].Checked) {
                        Toggle-AllCheckboxes $true
                    } else {
                        Toggle-AllCheckboxes $false
                    }
                }
            })
        } else {
            $checkbox.Add_CheckedChanged({
                if ($eventHandlingEnabled) {
                    if (-not $checkbox.Checked) {
                        $eventHandlingEnabled = $false
                        $checkboxes["All"].Checked = $false
                        $eventHandlingEnabled = $true
                    } else {
                        Check-AllState
                    }
                }
            })
        }

        # Add checkboxes to form controls
        $form.Controls.Add($checkbox)
        $index++
    }

    # Set Default Choices
    if ($DefaultChoice -contains 0) {
        $checkboxes["All"].Checked = $true
        Toggle-AllCheckboxes $true
    } else {
        foreach ($choiceIndex in $DefaultChoice) {
            if ($choiceIndex -ge 1 -and $choiceIndex -le $Options.Count) {
                $checkboxes[$Options[$choiceIndex - 1]].Checked = $true
            }
        }
    }

    # Submit Button
    $submitButton = New-Object System.Windows.Forms.Button
    $submitButton.Text = "Submit"
    $submitButton.Size = New-Object System.Drawing.Size(80, 30)
    $submitButton.Location = New-Object System.Drawing.Point(100, ($formHeight - 50))
    $submitButton.Add_Click({
        $script:result = @()
        if ($checkboxes["All"].Checked) {
            $script:result = "All"
        } else {
            foreach ($key in $checkboxes.Keys) {
                if ($checkboxes[$key].Checked -and $key -ne "All") {
                    $script:result += $key
                }
            }
        }
        $form.Close()
    })
    $form.Controls.Add($submitButton)

    # Show Form
    [void]$form.ShowDialog()
    return $result
}


Function Get-IdentityURL($idURL) {
    Add-Type -AssemblyName System.Net.Http

    Function CreateHttpClient($allowAutoRedirect) {
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.AllowAutoRedirect = $allowAutoRedirect
        return New-Object System.Net.Http.HttpClient($handler)
    }

    $client = CreateHttpClient($true)

    try {
        $task = $client.GetAsync($idURL)
        $task.Wait()  # Ensures the task completes and exceptions are thrown if any.

        if ($task.IsCompleted) {
            $response = $task.Result

            if (($response.StatusCode -ge 300 -and $response.StatusCode -lt 400) -or ($response.StatusCode -eq "OK")) {
                return $response.RequestMessage.RequestUri.Host
            } else {
                return "Unexpected status code: $($response.StatusCode)"
            }
        } else {
            return "Task did not complete successfully."
        }
    }
    catch {
        # Extracting detailed exception message from AggregateException
        $exception = $_.Exception
        while ($exception.InnerException) {
            $exception = $exception.InnerException
        }
        
        # Return the extracted exception message
        return "Error: $($exception.Message)"
    }
    finally {
        if ($client -ne $null) {
            $client.Dispose()
        }
    }
}

function Set-NetworkReqTemplate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, HelpMessage='Please provide the template path')]
        [ValidateNotNullOrEmpty()]
        [string]$template,

        [Parameter(Mandatory=$true, HelpMessage='Please provide the array of place holders')]
        [ValidateNotNullOrEmpty()]
        [array]$placeholders,

        [Parameter(Mandatory=$true, HelpMessage='Please provide the array of placeholder values')]
        [ValidateNotNullOrEmpty()]
        [array]$placeholderValues,

        [Parameter(Mandatory=$true, HelpMessage='Please provide the output file full path')]
        [ValidateNotNullOrEmpty()]
        [string]$outputFilePath
    )

    begin {
        $templateData = Get-Content -Path $template -Raw
    }

    process {
        for($i = 0; $i -lt $placeholders.Count; $i++){
            $templateData = $templateData -replace $placeholders[$i], $placeholderValues[$i]
        }

    }

    end {
        Write-Host $template
        $templateData | Set-Content -Path $outputFilePath
    }
}



# @FUNCTION@ ======================================================================================================================
# Name...........: CPMConnectionTest
# Description....: Performs multiple Casos calls against a vault
# Parameters.....: UserName, Password, VaultIP
# Return Values..: stdout txt file
# =================================================================================================================================
Function CPMConnectionTest(){
#Static
$VaultOperationFolder1 = "$PSScriptRoot\VaultOperationsTester"
$VaultOperationFolder2 = "$(Split-Path $PSScriptRoot -Parent)\VaultOperationsTester"

 #Prereqs   
if(Test-Path -Path "$VaultOperationFolder1\VaultOperationsTester.exe") {
    $VaultOperationFolder = $VaultOperationFolder1
} elseif(Test-Path -Path "$VaultOperationFolder2\VaultOperationsTester.exe") {
    $VaultOperationFolder = $VaultOperationFolder2
} else {
    Write-LogMessage -Type Error -Msg "Required file 'VaultOperationsTester.exe' doesn't exist in expected folders: `"$VaultOperationFolder1`" or `"$VaultOperationFolder2`". Make sure you get the latest version and extract it correctly from zip."
    Pause
    Return
}

$stdoutFile = "$VaultOperationFolder\Log\stdout.log"
$LOG_FILE_PATH_CasosArchive = "$VaultOperationFolder\Log\old"
$ZipToupload = "$VaultOperationFolder\_CPMConnectionTestLog"

    #Fetch values from .ini file
    $parameters = Try{Import-CliXML -Path $CONFIG_PARAMETERS_FILE}catch{Write-LogMessage -type Info -MSG "$($_.exception.message)" -Early}
    
    if($parameters){
        if (-not($parameters.contains("CPMConnectionTestPassed")))
        # if entry is not found, we proceed with test
        { 
            Write-LogMessage -type Info -MSG "** Since Vault Connectivity test passed, let's also run CPM Connection Install Test **"
            Write-LogMessage -type Info -MSG "** You will need to provide your Privilege Cloud Install Username and Password. **"
            #Ask if User wants to perform the test, subsequent runs won't show this question, you can only trigger this from Troubleshooting or -Switch.
            $decisionCPM = Get-Choice -Title "Run CPM Install Connection test?" -Options "Yes (Recommended)", "No" -DefaultChoice 1
            if ($decisionCPM -eq "No")
            {
                Write-LogMessage -type Warning -MSG "OK, if you change your mind, you can always rerun the script with -CPMConnectionTest flag (or -Troubleshooting and selecting from menu)."
                Pause
                return
            }
        }
        ElseIf($CPMConnectionTest)
        {
            #RunTheCheck
        }
        Else
        {
            Return
        }

    }

 # redis++
$redistributables = @(
    #@{ Name = "Microsoft Visual C++ 2013 x86*"; Path = "$VaultOperationFolder\vcredist_x86.exe" }, #2013 obsolete
    @{ Name = "Microsoft Visual C++ 2022 X86*"; Path = "$VaultOperationFolder\vc_redist.x86.exe" }, #2015-2022 86bit
    @{ Name = "Microsoft Visual C++ 2022 X64*"; Path = "$VaultOperationFolder\vc_redist.x64.exe" } #2015-2022 64bit
)

# Loop through each redistributable and check if it's installed
foreach ($redis in $redistributables) {
    if ((Get-CimInstance -Class win32_product | where {$_.Name -like $redis.Name}) -eq $null) {
        Write-LogMessage -type Info -MSG "Installing Redis++ from $($redis.Path)..." -Early
        Start-Process -FilePath $redis.Path -ArgumentList "/install /passive /norestart" -Wait
    }
}

        
        
        #Cleanup log file if it gets too big
        if (Test-Path $LOG_FILE_PATH_CasosArchive)
        {
            if (Get-ChildItem $LOG_FILE_PATH_CasosArchive | measure -Property length -Sum | where { $_.sum -gt 5MB })
            {
                Write-LogMessage -type Info -MSG "Archive log folder is getting too big, deleting it." -Early
                Write-LogMessage -type Info -MSG "Deleting $LOG_FILE_PATH_CasosArchive" -Early
                Remove-Item $LOG_FILE_PATH_CasosArchive -Recurse -Force
            }
        }
        
        #create file
        New-Item -Path $stdoutFile -Force | Out-Null
        Write-LogMessage -type Info -MSG "Begin CPM Connection Install Test"
        #Check if we can pull the Vault IP from the .ini file, otherwise prompt for it.
        if($parameters.VaultIP -eq $null){
            $VaultIP = Read-Host "Please enter your Vault Address"
        }
        Else{
            $VaultIP = $parameters.VaultIP
        }
        #Get Credentials
        Write-LogMessage -type Info -MSG "Enter Privilege Cloud InstallerUser Credentials"
		$creds = Get-Credential -Message "Enter Privilege Cloud InstallerUser Credentials"
		if($($creds.username) -match ' ' -or $($creds.GetNetworkCredential().Password) -match ' '){
			Write-Host "Your Username/password has a space in it. We would fix it, but you may end up pasting it somewhere and wonder why it doesn't work :)" -ForegroundColor Yellow
			Write-Host "Remove it and try again." -ForegroundColor Yellow
			Pause
            return
		}
        #Check pw doesn't contain illegal char, otherwise installation will fail
        [string]$illegalchars = '\/<>{}''&"$*@`|'
        $pwerror = $null
        if($($creds.GetNetworkCredential().Password).StartsWith('#')){
            Write-Host "illegal char detected # in first position" -ForegroundColor Red
            $pwerrorfirstchar = $true
        }
        foreach($char in $illegalchars.ToCharArray()){
            if ($($creds.GetNetworkCredential().Password).ToCharArray() -contains $char){
                Write-Host "illegal char detected $char" -ForegroundColor Red
                $pwerror = $true
            }
        }
        if($pwerrorfirstchar){
            Write-LogMessage -type Error -MSG "Password cannot start with a # as it will comment the rest of the line in powershell"
        }
        if($pwerror){
            Write-LogMessage -type Error -MSG "While the password can be set with high complexity in the vault post install, we require a simpler password just for the installation itself, make sure to not use the following chars: $illegalchars"
        }
        if($pwerror -or $pwerrorfirstchar){
            Write-LogMessage -type Error -MSG "Rerun the script with -CPMConnectionTest flag."
            Return
        }
    
        Write-LogMessage -type Success -MSG "Begin checking connection elements, should take 10-40 sec."
        $cleanupFromPreviousRuns = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($creds.UserName) $($creds.GetNetworkCredential().Password) $VaultIP CleanUp" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        $process = Start-Process -FilePath "$VaultOperationFolder\VaultOperationsTester.exe" -ArgumentList "$($creds.UserName) $($creds.GetNetworkCredential().Password) $VaultIP" -WorkingDirectory "$VaultOperationFolder" -NoNewWindow -PassThru -Wait -RedirectStandardOutput $stdoutFile
        $creds = $null
        $stdout = (gc $stdoutFile)
            if($process.ExitCode -ne 0){
                #Compress the logs for easy support case upload
                Compress-Archive -Path "$VaultOperationFolder\Log" -CompressionLevel NoCompression -Force -DestinationPath $ZipToupload
                If($stdout -match "ITATS203E Password has expired"){
                    Write-LogMessage -type Error -MSG "You must first reset your initial password in the PVWA Portal, then you can rerun this test again by simply invoking the script with -CPMConnectionTest flag or -Troubleshooting flag and choose 'Run CPM Install Connection Test' option."
                    Pause
                    Break
                }
                Write-LogMessage -type Warning -MSG "Failed to simulate a healthy CPM install:"
                Write-Host "-----------------------------------------"
                $stdout | Select-String -Pattern 'Extra details' -NotMatch | Write-Host -ForegroundColor DarkGray
                Write-LogMessage -type Error -MSG "$($stdout | Select-String -Pattern 'Extra details')"
                
                Write-Host "-----------------------------------------"
                Write-LogMessage -type Warning -MSG "1) More detailed log can be found here: $VaultOperationFolder\Log\Casos.Error.log"
                Write-LogMessage -type Warning -MSG "2) Logs folder was zipped (Use for Support Case): `"$ZipToupload.zip`""
                [int]$lasthint = 4
                If($stdout -match "ITACM040S"){
                    # [int]$lasthint = $lasthint+1
                    Write-LogMessage -type Warning -MSG "3) In case of PA FW or similar configuration check out this page: "
                    Write-LogMessage -type Warning -MSG "   https://docs.cyberark.com/ispss-deployment/latest/en/Content/Privilege%20Cloud/Priv-Cloud-Firewall-setup.htm"
                }
                Else{
                    Write-LogMessage -type Warning -MSG "3) Hint: Typically this means there is a problem with Username/Password or FW configuration."
                }
                Write-LogMessage -type Warning -MSG "$lasthint) Rerun the script with -CPMConnectionTest flag."
            }
            Else{
                $stdout | Write-Host -ForegroundColor DarkGray
                Write-LogMessage -type Success -MSG "Connection is OK!"
                $dateTEST = $(get-date -format yyyyMMdd) + "_" + $(get-date -format HHmm)
                $machineNametrim = $($env:COMPUTERNAME).Substring($env:COMPUTERNAME.Length - 4)
                $dummypass = "Tdsa6sdf4gkj2gdo!"
                $dummyuser = "CPMConnectionTestPass_$($dateTEST)_$($machineNametrim)"
                $logonBody = @{ username = "$($dummyuser)" ; password = "$($dummypass)" } | ConvertTo-Json -Compress
                Try
                {
                    $targetUriString = "https://$($VaultIP.TrimStart("vault-"))/passwordvault/api/Auth/CyberArk/Logon"
                    $targetUri = [Uri]$targetUriString
                    $systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
                    $systemProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials # Use this if your proxy requires authentication
                    $proxyUri = $systemProxy.GetProxy($targetUri)
                    
                    if ($proxyUri.Host -ne $targetUri.Host)
                    {
                        # If the hosts are different, use the proxy
                        $response = Invoke-RestMethod -Uri $targetUriString -ContentType "application/json" -Method Post -ErrorVariable pvwaERR -Body $logonBody -Proxy $proxyUri.AbsoluteUri
                    }
                    else
                    {
                        # If the hosts are the same, don't use the proxy
                        $response = Invoke-RestMethod -Uri $targetUriString -ContentType "application/json" -Method Post -ErrorVariable pvwaERR -Body $logonBody
                    }
                }
                Catch
                {
                    if($pvwaERR -like "*Authentication failure for User*"){
                        Write-LogMessage -type Success -MSG "Sent a signal to our backend of this sucessful test @ TIME: $($dateTEST)"
                    }Else{
                        Write-LogMessage -type Warning -MSG "Failed to send a dummy string to CyberArk backend to signal that your prereq passed successfully, that's ok its optional anyway."
                    }
                        
                }
                Write-LogMessage -type Success -MSG "If you want to rerun this check in the future, run the script with -CPMConnectionTest or -Troubleshooting."

            # Add entry to ini file that this test passed and skip it from now on.
            Remove-Item -Path $CONFIG_PARAMETERS_FILE -Force -ErrorAction SilentlyContinue
            Try{
                $parameters += @{
                    CPMConnectionTestPassed = $True
                    LastSuccessfulCPMPassDate = (Get-Date -Format "yyyy-MM-dd")
                }
            }
            Catch{}
            $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII -Force
            }
}



# @FUNCTION@ ======================================================================================================================
# Name...........: Set-ScriptParameters
# Description....: Stores variable for all user input fields
# Parameters.....: VaultIP, TunnelIP, PortalURL
# Return Values..: True/False
# =================================================================================================================================
Function Set-ScriptParameters()
{
[CmdletBinding(DefaultParameterSetName="Regular")]
param
(
	# Get the Portal URL
	[Parameter(ParameterSetName='Regular',Mandatory=$true, HelpMessage="Example: https://<customerDomain>.privilegecloud.cyberark.cloud")]
	[AllowEmptyString()]
	[Alias("PortalURL")]
	[ValidateScript({
		If(![string]::IsNullOrEmpty($_)) {
			($_ -like "*.privilegecloud.cyberark.com*") -or ($_ -like "*.cyberark.cloud*")
		}
		Else { $true }
	})]
	[String]${Please enter your provided portal URL Address (Or leave empty)},
	# Config File
	[Parameter(ParameterSetName='File',Mandatory=$true)]
	[ValidateScript({Test-Path $_})]
	[String]$ConfigFile  
 )

	 If([string]::IsNullOrEmpty($ConfigFile))
	 {
        # ------ Copy parameter values entered ------
        $script:PortalURL = ${Please enter your provided portal URL Address (Or leave empty)}
        # grab the subdomain, depending how the user entered the url (hostname only or URL).
        if($script:portalURL -match "https://"){
            $script:portalURL = ([System.Uri]$script:PortalURL).host
            $script:portalSubDomainURL = $portalURL.Split(".")[0]
        }
        Else{
            $script:portalSubDomainURL = $PortalURL.Split(".")[0]
        }

        # Check if standard or shared services implementation.
        if($PortalURL -like "*.privilegecloud.cyberark.com*"){
            # Standard
            $script:VaultIP = "vault-$portalSubDomainURL.privilegecloud.cyberark.com"
            $script:TunnelIP = "connector-$portalSubDomainURL.privilegecloud.cyberark.com"
        }Elseif($PortalURL -like "*.cyberark.cloud*"){
            # ispss
            $script:testComponents = Get-MultipleChoice -Title "Select Components To Test" -Options "All","SIA - Secure Infrastructure Access (DPA)","CM - Connector Management","PSM - Privilege Session Manager","CPM - Central Policy Manager","ST - Secure Tunnel (Legacy HTML5, SIEM)" -DefaultChoice @(2,3,5)
            Write-Host "Selected:`n$($testComponents -join "`n")"
            $script:VaultIP = "vault-$portalSubDomainURL.privilegecloud.cyberark.cloud"
            $script:TunnelIP = "connector-$portalSubDomainURL.privilegecloud.cyberark.cloud"
        }Elseif($portalSubDomainURL -eq $null){
            # user didn't enter anything, do nothing in this case, so it skips the connection test.
        }
			
		# Create the Config file for next use
		$parameters = @{
			PortalURL = $PortalURL.Trim()
			VaultIP = $VaultIP.trim()
			TunnelIP = $TunnelIP.trim()
            testComponents = $testComponents.trim()
		}
		$parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII
        # deal with ispss
        if($PortalURL -like "*.privilegecloud.cyberark.com*"){$script:g_ConsoleIP = $g_ConsoleIPstd}else{$script:g_ConsoleIP = $g_ConsoleIPispss}
	 }
	 else{
		$parameters = Import-CliXML -Path $CONFIG_PARAMETERS_FILE
		$script:VaultIP = $parameters.VaultIP
		$script:TunnelIP = $parameters.TunnelIP
		$script:PortalURL = $parameters.PortalURL
        $script:LastSuccessfulCPMPassDate = $parameters.LastSuccessfulCPMPassDate
        $script:testComponents = $parameters.testComponents
        # deal with ispss
        if($PortalURL -like "*.privilegecloud.cyberark.com"){$script:g_ConsoleIP = $g_ConsoleIPstd}else{$script:g_ConsoleIP = $g_ConsoleIPispss}
	 }
    
    # Show the user the primary params we are going to check against.
    Write-LogMessage -Type Info -SubHeader -Msg "Privilege Cloud Tenant Details:"
    Write-LogMessage -type Success -MSG "Portal: $PortalURL"
    Write-LogMessage -type Success -MSG "Vault:  $VaultIP"

    # Check when was last time CPMConnectionTest ran, we want this to be fresh atleast 3 days before install date.
    if($parameters.LastSuccessfulCPMPassDate)
    {
        # Convert the string date to DateTime for comparison
        $lastSuccessDate = [DateTime]::ParseExact($parameters.LastSuccessfulCPMPassDate, "yyyy-MM-dd", $null)
        
        # Calculate the diff
        $daysSinceLastSuccess = (Get-Date) - $lastSuccessDate

        if($daysSinceLastSuccess.Days -gt 2)
        {
            Write-LogMessage -type Error -MSG ("Last successful CPMConnectionTest was: " + $lastSuccessDate.ToString("yyyy-dd-MM") + ", let's run it again using -CPMConnectionTest.")
        }
        else
        {
            Write-LogMessage -type Success -MSG ("Last successful CPMConnectionTest was: " + $lastSuccessDate.ToString("yyyy-dd-MM"))
        }
    }
    else 
    {
        # If the value doesn't exist
        Write-LogMessage -type Info -MSG "Last successful CPMConnectionTest was: not yet performed." -Early
    }
}

Function AddLineToTable($action, $resultObject)
{

	$addLine = $false

    if ($resultObject.result -and $resultObject.errorMsg -ne "")
	{
        $mark = '[V]'
        $resultStr = "Warning"
        $addLine = $true
    }

    elseif (!$resultObject.result)
    {
        $mark = '[X]'
        $resultStr = "Failure"
        $addLine = $true
    }

    if ($addLine)
    {
        $objAverage = New-Object System.Object
        #$objAverage | Add-Member -type NoteProperty -name '   ' -value $mark
        $objAverage | Add-Member -type NoteProperty -name Result -value $resultStr
        $objAverage | Add-Member -type NoteProperty -name Check -value $action
        $objAverage | Add-Member -type NoteProperty -Name Expected -Value $resultObject.expected
        $objAverage | Add-Member -type NoteProperty -Name Actual -Value $resultObject.actual
        $objAverage | Add-Member -type NoteProperty -Name Description -Value $resultObject.errorMsg
        
        $global:table += $objAverage
    }
}

Function AddLineToReport($action, $resultObject)
{

    $status = 'FAILED'
    $line = ""
	$errMessage = $resultObject.errorMsg

    $actionPad = $action

    if($resultObject.errorMsg -ne "")
    {
        $errMessage= "- $errMessage"
    }

	if($resultObject.result)
	{
        $mark = '[V]'
        $status = 'PASS'

        $line = "$mark $actionPad $errMessage"
        if($errMessage-ne "")
        {
            Write-LogMessage -Type Warning -Msg $line
        }
        else
        { 
            Write-LogMessage -Type Success -Msg $line 
        }
    }
    else
    {
        $mark = '[X]'
        $line = "$mark $actionPad $errMessage"
        Write-LogMessage -Type Error -Msg $line
    }
}
 
Function CheckPrerequisites {
    Param (
        [String[]]$selectedComponents
    )
    
    Try {
        $global:table = @()
        $errorCnt = 0
        $warnCnt = 0
        $table = ""

        # Track executed methods
        $executedMethods = @{}

        # General checks
        Write-LogMessage -Type Warning -Msg "< General Related Checks >"
        foreach ($method in $arrCheckPrerequisitesGeneral) {
            if (-not $executedMethods[$method]) {
                Try {
                    Write-Progress -Activity "Checking $method..."
                    $resultObject = &$method

                    if ($null -eq $resultObject -or !$resultObject.result) {
                        $errorCnt++
                    }

                    Write-Progress -Activity "$method completed" -Completed
                }
                Catch {
                    $resultObject.errorMsg = $_.Exception.Message
                    $errorCnt++
                }

                if ($resultObject.errorMsg -ne $g_SKIP) {
                    AddLineToReport $method $resultObject
                } else {
                    $resultObject.errorMsg = ""
                }

                AddLineToTable $method $resultObject
                $executedMethods[$method] = $true
            }
        }

        # Specific checks by component
        $componentsToCheck = if ($selectedComponents -contains "All") {
            $componentMapping.Keys # All components if "All" is selected
        } else {
            $selectedComponents
        }

        foreach ($component in $componentsToCheck) {
            $arrToCheck = $componentMapping[$component]
            
            if ($arrToCheck -ne $null) {
                # Log component-specific checks
                Write-LogMessage -Type Warning -Msg "< $component Related Checks >"
                
                foreach ($method in $arrToCheck) {
                    if (-not $executedMethods[$method]) {
                        Try {
                            Write-Progress -Activity "Checking $method..."
                            $resultObject = &$method  

                            if ($null -eq $resultObject -or !$resultObject.result) {
                                $errorCnt++
                            }

                            Write-Progress -Activity "$method completed" -Completed
                        }
                        Catch {
                            $resultObject.errorMsg = $_.Exception.Message
                            $errorCnt++
                        }

                        if ($resultObject.errorMsg -ne $g_SKIP) {
                            AddLineToReport $method $resultObject
                        } else {
                            $resultObject.errorMsg = ""
                        }

                        AddLineToTable $method $resultObject
                        $executedMethods[$method] = $true
                    }
                }
            }
        }

        # Final logging of errors and warnings
        if ($global:table.Count -gt 0) {
            $warnCnt = $global:table.Count - $errorCnt
            Write-LogMessage -Type Info -Msg "Checking Prerequisites completed with $errorCnt failures and $warnCnt warnings."
            Write-LogMessage -Type Info -Msg "$SEPARATE_LINE"
            $global:table | Format-Table -Wrap
            Write-LogMessage -Type LogOnly -Msg $($global:table | Out-String)
        } else {
            Write-LogMessage -Type Success -Msg "Checking Prerequisites completed successfully"
        }
    }
    Catch {
        Throw $(New-Object System.Exception("CheckPrerequisites: Failed to run CheckPrerequisites", $_.Exception))
    }
}






# @FUNCTION@ ======================================================================================================================
# Name...........: Test-VersionUpdate
# Description....: Tests the latest version and downloads the latest script if found
# Parameters.....: None
# Return Values..: None
# =================================================================================================================================
Function Test-VersionUpdate()
{
	# Define the URLs to be used
	$pCloudServicesURL = "https://raw.githubusercontent.com/pCloudServices/cmprereq/master"
	$pCloudLatest = "$pCloudServicesURL/Latest.txt"
	$pCloudScript = "$pCloudServicesURL/$g_ScriptName"
	
	Write-LogMessage -Type Info -Msg "Checking for new version" -Early
	$checkVersion = ""
	$webVersion = New-Object System.Net.WebClient

#Ignore certificate error
if (-not ([System.Management.Automation.PSTypeName]'ServerCertificateValidationCallback').Type)
    {
		$certCallback = @"
			using System;
			using System.Net;
			using System.Net.Security;
			using System.Security.Cryptography.X509Certificates;
			public class ServerCertificateValidationCallback
			{
				public static void Ignore()
				{
					if(ServicePointManager.ServerCertificateValidationCallback ==null)
					{
						ServicePointManager.ServerCertificateValidationCallback += 
							delegate
							(
								Object obj, 
								X509Certificate certificate, 
								X509Chain chain, 
								SslPolicyErrors errors
							)
							{
								return true;
							};
					}
				}
			}
"@
			Add-Type $certCallback
	}
	[ServerCertificateValidationCallback]::Ignore()
    #ERROR: The request was aborted: Could not create SSL/TLS secure channel.
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    
	Try
	{
		$resWebCall = (Invoke-WebRequest -UseBasicParsing -Uri $pCloudLatest -ErrorAction Stop)
		If($resWebCall.StatusCode -eq "200")
		{
			[int]$checkVersion = $resWebCall.Content.trim()
		}
	}
	Catch
	{
		Write-LogMessage -Type Info -Msg "Test-VersionUpdate: Couldn't check for latest version, probably DNS/FW Issue: $(Collect-ExceptionMessage $_.Exception.Message)" -Early
        return # no need to run the rest if can't reach git.
	}

	If ($checkVersion -gt $versionNumber)
	{
		Write-LogMessage -Type Info -Msg "Found new version: $checkVersion Updating..."
		Try
		{
			Invoke-WebRequest -UseBasicParsing -Uri $pCloudScript -ErrorAction Stop -OutFile "$PSCommandPath.NEW"
		}
		Catch
		{
			Throw $(New-Object System.Exception ("Test-VersionUpdate: Couldn't download latest version",$_.Exception))
		}

		If (Test-Path -Path "$PSCommandPath.NEW")
		{
			Rename-Item -path $PSCommandPath -NewName "$PSCommandPath.OLD"
			Rename-Item -Path "$PSCommandPath.NEW" -NewName $g_ScriptName
			Remove-Item -Path "$PSCommandPath.OLD"
            $scriptPathAndArgs = "& `"$g_ScriptName`" -OutOfDomain:$OutOfDomain -Troubleshooting:$Troubleshooting -InstallRDS:$InstallRDS -DisableNLA:$DisableNLA -skipVersionCheck:$SkipVersionCheck -SkipIPCheck:$SkipIPCheck"
			Write-LogMessage -Type Info -Msg "Finished Updating, please relaunch script."
			Pause
			Exit
		}
		Else
		{
			Write-LogMessage -Type Error -Msg "Can't find the new script at location '$PSScriptRoot'."
		}
	}
	Else
	{
		Write-LogMessage -Type Info -Msg "Current version is the latest!" -Early
	}
}

#endregion

#region Writer Functions
# @FUNCTION@ ======================================================================================================================
# Name...........: Write-LogMessage
# Description....: Writes the message to log and screen
# Parameters.....: LogFile, MSG, (Switch)Header, (Switch)SubHeader, (Switch)Footer, Type
# Return Values..: None
# =================================================================================================================================
Function Write-LogMessage
{
<# 
.SYNOPSIS 
	Method to log a message on screen and in a log file

.DESCRIPTION
	Logging The input Message to the Screen and the Log File. 
	The Message Type is presented in colours on the screen based on the type

.PARAMETER LogFile
	The Log File to write to. By default using the LOG_FILE_PATH
.PARAMETER MSG
	The message to log
.PARAMETER Header
	Adding a header line before the message
.PARAMETER SubHeader
	Adding a Sub header line before the message
.PARAMETER Footer
	Adding a footer line after the message
.PARAMETER Type
	The type of the message to log (Info, Warning, Error, Debug)
#>
	param(
		[Parameter(Mandatory=$true, ValueFromPipeline=$true)]
		[AllowEmptyString()]
		[String]$MSG,
		[Parameter(Mandatory=$false)]
		[Switch]$Header,
		[Parameter(Mandatory=$false)]
		[Switch]$Early,
		[Parameter(Mandatory=$false)]
		[Switch]$SubHeader,
		[Parameter(Mandatory=$false)]
		[Switch]$Footer,
		[Parameter(Mandatory=$false)]
		[ValidateSet("Info","Warning","Error","Debug","Verbose", "Success", "LogOnly")]
		[String]$type = "Info",
		[Parameter(Mandatory=$false)]
		[String]$LogFile = $LOG_FILE_PATH
	)
	Try{
		If ($Header) {
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
		ElseIf($SubHeader) { 
			"------------------------------------" | Out-File -Append -FilePath $LogFile 
			Write-Host "------------------------------------" -ForegroundColor Magenta
		}
		
		$msgToWrite = "[$(Get-Date -Format "yyyy-MM-dd hh:mm:ss")]`t"
		$writeToFile = $true
		# Replace empty message with 'N/A'
		if([string]::IsNullOrEmpty($Msg)) { $Msg = "N/A" }
		
		# Mask Passwords
		if($Msg -match '((?:password|credentials|secret)\s{0,}["\:=]{1,}\s{0,}["]{0,})(?=([\w`~!@#$%^&*()-_\=\+\\\/|;:\.,\[\]{}]+))')
		{
			$Msg = $Msg.Replace($Matches[2],"****")
		}
		# Check the message type
		switch ($type)
		{
			{($_ -eq "Info") -or ($_ -eq "LogOnly")} 
			{ 
				If($_ -eq "Info")
				{
					Write-Host $MSG.ToString() -ForegroundColor $(If($Header -or $SubHeader) { "magenta" } Elseif($Early){"DarkGray"} Else { "White" })
				}
				$msgToWrite += "[INFO]`t$Msg"
			}
			"Success" { 
				Write-Host $MSG.ToString() -ForegroundColor Green
				$msgToWrite += "[SUCCESS]`t$Msg"
            }
			"Warning" {
				Write-Host $MSG.ToString() -ForegroundColor Yellow
				$msgToWrite += "[WARNING]`t$Msg"
			}
			"Error" {
				Write-Host $MSG.ToString() -ForegroundColor Red
				$msgToWrite += "[ERROR]`t$Msg"
			}
			"Debug" { 
				if($InDebug -or $InVerbose)
				{
					Write-Debug $MSG
					$msgToWrite += "[DEBUG]`t$Msg"
				}
				else { $writeToFile = $False }
			}
			"Verbose" { 
				if($InVerbose)
				{
					Write-Verbose -Msg $MSG
					$msgToWrite += "[VERBOSE]`t$Msg"
				}
				else { $writeToFile = $False }
			}
		}

		If($writeToFile) { $msgToWrite | Out-File -Append -FilePath $LogFile }
		If ($Footer) { 
			"=======================================" | Out-File -Append -FilePath $LogFile 
			Write-Host "=======================================" -ForegroundColor Magenta
		}
	}
	catch{
		Throw $(New-Object System.Exception ("Cannot write message"),$_.Exception)
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: Collect-ExceptionMessage
# Description....: Formats exception messages
# Parameters.....: Exception
# Return Values..: Formatted String of Exception messages
# =================================================================================================================================
Function Collect-ExceptionMessage
{
<# 
.SYNOPSIS 
	Formats exception messages
.DESCRIPTION
	Formats exception messages
.PARAMETER Exception
	The Exception object to format
#>
	param(
		[Exception]$e
	)

	Begin {
	}
	Process {
		$msg = "Source:{0}; Message: {1}" -f $e.Source, $e.Message
		while ($e.InnerException) {
		  $e = $e.InnerException
		  $msg += "`n`t->Source:{0}; Message: {1}" -f $e.Source, $e.Message
		}
		return $msg
	}
	End {
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogHeader
# Description....: Creates the log header
# Parameters.....: None
# Return Values..: The HEader string 
# =================================================================================================================================
Function Get-LogHeader
{
    return @"
	
###########################################################################################
#
#                       Privilege Cloud Pre-requisites Check PowerShell Script
#
# Version : $versionNumber
# CyberArk Software Ltd.
###########################################################################################
"@
}

# @FUNCTION@ ======================================================================================================================
# Name...........: Get-LogoHeader
# Description....: Creates the logo header
# Parameters.....: None
# Return Values..: The Header image
# =================================================================================================================================
Function Get-LogoHeader {
    $t = @"
  ____      _                _         _    
 / ___|   _| |__   ___ _ __ / \   _ __| | __
| |  | | | | '_ \ / _ \ '__/ _ \ | '__| |/ /
| |__| |_| | |_) |  __/ | / ___ \| |  |   < 
 \____\__, |_.__/ \___|_|/_/   \_\_|  |_|\_\
      |___/ 

"@

    for ($i=0; $i -lt $t.Length; $i++) {
        $c = "black"  # Default color

        if ($i % 2 -eq 0) {
            $c = "red"
        }
        elseif ($i % 3 -eq 0) {
            $c = "green"
        }
        elseif ($i % 5 -eq 0) {
            $c = "black"
        }
        elseif ($i % 7 -eq 0) {
            $c = "green"
        }
        elseif ($i % 11 -eq 0) {
            $c = "green"
        }
        elseif ($i % 13 -eq 0) {
            $c = "red"
        }

        Write-Host $t[$i] -NoNewline -ForegroundColor $c
    }
}

#endregion

#region Main Script
###########################################################################################
# Main start
###########################################################################################
if($psISE -ne $null){
    Write-Host "You're not suppose to run this from ISE."
    Pause
    Exit
}

$Host.UI.RawUI.WindowTitle = "Privilege Cloud Connector Management Prerequisites Check"

#Cleanup log file if it gets too big
if (Test-Path $LOG_FILE_PATH)
{
    if (Get-ChildItem $LOG_FILE_PATH -File | Where-Object { $_.Length -gt 5000KB })
    {
        Write-LogMessage -type Info -MSG "Log file is getting too big, deleting it."
        Remove-Item $LOG_FILE_PATH -Force
    }

}

Write-LogMessage -Type Info -Msg $(Get-LogHeader) -Header
Get-LogoHeader
Write-LogMessage -Type Verbose -Msg "Verify user is a local Admin"
$adminUser = IsUserAdmin 
# Run only if the User is a local admin on the machine
If ($adminUser -eq $False)
{
	Write-LogMessage -Type Error -Msg "You must logged on as a local administrator in order to run this script"
    pause
	return
}
    #troubleshooting section
if ($Troubleshooting){Troubleshooting}
    #Run CPM Install Test with direct flag
if ($CPMConnectionTest){CPMConnectionTest}
else
{
	try {
        # Check the latest version
		if(! $SkipVersionCheck){
            Write-LogMessage -Type Info -Msg "Checking for latest version" -Early
            Test-VersionUpdate 
        }
        Else{ Write-LogMessage -Type Info -Msg "Skipped version check" -Early }
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to check for latest version - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
    try {
        # Disable NLA after RDS deployment and machine restart
        if($DisableNLA){
            Disable-NLA
            Exit
        }
		
        # Resume RDS from Scheduled Task or if called with a flag on script exec
        if($InstallRDS){
            InstallRDS
        }

		if(Test-Path $CONFIG_PARAMETERS_FILE)
		{
			Write-LogMessage -type Info -MSG "Getting parameters from config file '$CONFIG_PARAMETERS_FILE'" -Early
			Set-ScriptParameters -ConfigFile $CONFIG_PARAMETERS_FILE
            #CheckConnectionToVault
		}
		else
		{
            #In case user placed ConnectionDetails.txt file in the same folder we can grab all the values from it.
            Write-LogMessage -type Info -MSG "Checking if ConnectionDetails.txt file exist so we can fetch values from there instead of manually typing them." -Early
            $ConnectionDetailsFile = "$PSScriptRoot\*ConnectionDetails.txt"    
            if (Test-Path $ConnectionDetailsFile){
                $script:PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:")).Host
                #Deal with TM format
                if($PortalURL -eq $null)
                    {
                    $script:PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:").Trim()).OriginalString
                    }
                if($PortalURL -match "https://")
	                {
		            $script:PortalURL = ([System.Uri]$PortalURL).Host
	                }
                $VaultIP = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "VaultIp:").ToString().ToLower().trim("vaultip:").Trim()
                $TunnelIP = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "ConnectorServerIp:").ToString().ToLower().trim("connectorserverip:").Trim()

                $parameters = @{
			        PortalURL = $PortalURL
			        VaultIP = $VaultIP
			        TunnelIP = $TunnelIP
		        }
		        $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII
		    }
            ElseIf($PortalURL -match "https://")
            {
                $script:PortalURL = ([System.Uri]$PortalURL).Host
            }
            Else
            {
			    Write-LogMessage -type Info -MSG "Prompting user for input" -Early
			    Set-ScriptParameters #Prompt for user input
            }
		}
    } catch {
        Write-LogMessage -type Error -MSG "Failed to Prompt user for input - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
    }    
	try {
        # Retrieve public IP and save it locally
        if(! $SkipIPCheck){
		    Write-LogMessage -Type Verbose -Msg $(GetPublicIP)
        }
        Else{ Write-LogMessage -Type Info -Msg "Skipped Online IP check" -Early }
	} catch {
		Write-LogMessage -Type Error -Msg "Failed to retrieve public IP - Skipping. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	try {
        if($enforceTLS -eq $true){enforceTLS}

        # Main Pre-requisites check
		CheckPrerequisites -selectedComponents $testComponents

        # Install RDS on the Initial Run
        If($testComponents -like "*PSM - Privilege Session Manager*" -or "All"){checkIfPSMisRequired}

        # If VaultConnectivity passed, and no pending restart from InstallRDS, run CPM Test.
        if(($VaultConnectivityOK -eq $true) -and ($null -eq $CPMConnectionTestSkip)){CPMConnectionTest}

        # if network file template is missing, try downloading from git
        $networkFileTemplate = "network_template.txt"
        $networkReqFile = "network_requirements.txt"
        If(-not(Test-Path "$ScriptLocation\$networkFileTemplate")){
            Try{
                Write-LogMessage -type Info -MSG "Missing $networkFileTemplate Attemping to download from Github." -Early
                Invoke-WebRequest -URI "https://raw.githubusercontent.com/pCloudServices/cmprereq/main/$networkFileTemplate" -UseBasicParsing -TimeoutSec 20 -OutFile "$ScriptLocation\$networkFileTemplate"
            }Catch{}
        }
        # if file downloaded or already existed, check global params and populate template file
        if(Test-Path "$ScriptLocation\$networkFileTemplate"){
            $valuesExist = $null -ne $PortalURL -and
            $null -ne $IdentityHeaderURL -and
            $null -ne $region -and
            $null -ne $GetTenantDetails.Result.Name
            # if both file and variables exists lets set them in the template file.
            if($valuesExist){
                Set-NetworkReqTemplate -template "$ScriptLocation\$networkFileTemplate" -placeholders @("<Subdomain>","<tenant-id>","<AWSRegion>","<IdentityPod>") -placeholderValues @($($PortalURL.Split(".")[0]),$IdentityHeaderURL.Split('.')[0],$region,$($GetTenantDetails.Result.Name.Split('.')[0])) -outputFilePath "$ScriptLocation\$networkReqFile"
                Start-Process "$ScriptLocation\$networkReqFile"
            }Else{
                Write-LogMessage -type Info -MSG "Couldn't print network requirement file, that's ok, it's optional."
                write-host $PortalURL.Split(".")[0]
                Write-Host $IdentityHeaderURL
                Write-Host $region
                Write-Host $GetTenantDetails.Result.Name
            }
        }
               

	} catch	{
		Write-LogMessage -Type Error -Msg "Checking prerequisites failed. Error(s): $(Collect-ExceptionMessage $_.Exception)"
	}
}
Write-LogMessage -Type Info -Msg "Script Ended" -Footer
#########################################################
# SIG # Begin signature block
# MIIpJQYJKoZIhvcNAQcCoIIpFjCCKRICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCC3+PWSCgw7mR/z
# SG1tnIKbgbgSlqknfC2CTyj11FJwh6CCDpUwggboMIIE0KADAgECAhB3vQ4Ft1kL
# th1HYVMeP3XtMA0GCSqGSIb3DQEBCwUAMFMxCzAJBgNVBAYTAkJFMRkwFwYDVQQK
# ExBHbG9iYWxTaWduIG52LXNhMSkwJwYDVQQDEyBHbG9iYWxTaWduIENvZGUgU2ln
# bmluZyBSb290IFI0NTAeFw0yMDA3MjgwMDAwMDBaFw0zMDA3MjgwMDAwMDBaMFwx
# CzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTIwMAYDVQQD
# EylHbG9iYWxTaWduIEdDQyBSNDUgRVYgQ29kZVNpZ25pbmcgQ0EgMjAyMDCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMsg75ceuQEyQ6BbqYoj/SBerjgS
# i8os1P9B2BpV1BlTt/2jF+d6OVzA984Ro/ml7QH6tbqT76+T3PjisxlMg7BKRFAE
# eIQQaqTWlpCOgfh8qy+1o1cz0lh7lA5tD6WRJiqzg09ysYp7ZJLQ8LRVX5YLEeWa
# tSyyEc8lG31RK5gfSaNf+BOeNbgDAtqkEy+FSu/EL3AOwdTMMxLsvUCV0xHK5s2z
# BZzIU+tS13hMUQGSgt4T8weOdLqEgJ/SpBUO6K/r94n233Hw0b6nskEzIHXMsdXt
# HQcZxOsmd/KrbReTSam35sOQnMa47MzJe5pexcUkk2NvfhCLYc+YVaMkoog28vmf
# vpMusgafJsAMAVYS4bKKnw4e3JiLLs/a4ok0ph8moKiueG3soYgVPMLq7rfYrWGl
# r3A2onmO3A1zwPHkLKuU7FgGOTZI1jta6CLOdA6vLPEV2tG0leis1Ult5a/dm2tj
# IF2OfjuyQ9hiOpTlzbSYszcZJBJyc6sEsAnchebUIgTvQCodLm3HadNutwFsDeCX
# pxbmJouI9wNEhl9iZ0y1pzeoVdwDNoxuz202JvEOj7A9ccDhMqeC5LYyAjIwfLWT
# yCH9PIjmaWP47nXJi8Kr77o6/elev7YR8b7wPcoyPm593g9+m5XEEofnGrhO7izB
# 36Fl6CSDySrC/blTAgMBAAGjggGtMIIBqTAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUJZ3Q
# /FkJhmPF7POxEztXHAOSNhEwHwYDVR0jBBgwFoAUHwC/RoAK/Hg5t6W0Q9lWULvO
# ljswgZMGCCsGAQUFBwEBBIGGMIGDMDkGCCsGAQUFBzABhi1odHRwOi8vb2NzcC5n
# bG9iYWxzaWduLmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUwRgYIKwYBBQUHMAKGOmh0
# dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2NvZGVzaWduaW5ncm9v
# dHI0NS5jcnQwQQYDVR0fBDowODA2oDSgMoYwaHR0cDovL2NybC5nbG9iYWxzaWdu
# LmNvbS9jb2Rlc2lnbmluZ3Jvb3RyNDUuY3JsMFUGA1UdIAROMEwwQQYJKwYBBAGg
# MgECMDQwMgYIKwYBBQUHAgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3Jl
# cG9zaXRvcnkvMAcGBWeBDAEDMA0GCSqGSIb3DQEBCwUAA4ICAQAldaAJyTm6t6E5
# iS8Yn6vW6x1L6JR8DQdomxyd73G2F2prAk+zP4ZFh8xlm0zjWAYCImbVYQLFY4/U
# ovG2XiULd5bpzXFAM4gp7O7zom28TbU+BkvJczPKCBQtPUzosLp1pnQtpFg6bBNJ
# +KUVChSWhbFqaDQlQq+WVvQQ+iR98StywRbha+vmqZjHPlr00Bid/XSXhndGKj0j
# fShziq7vKxuav2xTpxSePIdxwF6OyPvTKpIz6ldNXgdeysEYrIEtGiH6bs+XYXvf
# cXo6ymP31TBENzL+u0OF3Lr8psozGSt3bdvLBfB+X3Uuora/Nao2Y8nOZNm9/Lws
# 80lWAMgSK8YnuzevV+/Ezx4pxPTiLc4qYc9X7fUKQOL1GNYe6ZAvytOHX5OKSBoR
# HeU3hZ8uZmKaXoFOlaxVV0PcU4slfjxhD4oLuvU/pteO9wRWXiG7n9dqcYC/lt5y
# A9jYIivzJxZPOOhRQAyuku++PX33gMZMNleElaeEFUgwDlInCI2Oor0ixxnJpsoO
# qHo222q6YV8RJJWk4o5o7hmpSZle0LQ0vdb5QMcQlzFSOTUpEYck08T7qWPLd0jV
# +mL8JOAEek7Q5G7ezp44UCb0IXFl1wkl1MkHAHq4x/N36MXU4lXQ0x72f1LiSY25
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB6UwggWNoAMCAQICDAJZP4AHVQPEmDE5
# fjANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjQwMzA0MTM1NzE4WhcNMjYwMzA1MTM1NzE4WjCB
# 6zEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxGTAXBgNVBAgT
# EENlbnRyYWwgRGlzdHJpY3QxFDASBgNVBAcTC1BldGFoIFRpa3ZhMR8wHQYDVQQK
# ExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZDeWJlckFyayBTb2Z0
# d2FyZSBMdGQuMSEwHwYJKoZIhvcNAQkBFhJhZG1pbkBjeWJlcmFyay5jb20wggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCW/EphpbQKOtU69jouawb8wLcd
# 1OFl4mjU/IwWs/F50xD/XtpkocmEjb5eQmzWDLjFjyaQc4+9lKZVmh5BJiH5O/4K
# Zh07tYcD/zWw1+ASFu9M/46znESl0Wu9T743zWm/8MNI21Z7GiXocpk3ca81IOsp
# PNVU/qyMMgU67gK2l48ywRVLposh2oQcU2oGofzk3GvfQ1Ej4/HfUaT0U45V+uMj
# +XyNo6QZcfCYQiv9TLqwhVzD/PDvo2IMDk153Vt7y4/PKi4eimip0a/sWoNQV8aD
# +iOF6qgBKdQ34l7nPWeAic1EnkOiBMPlukrmBxOo6qX3OOpoxByG8iQKCt2ZsJE1
# Jfg6r/p+idbbFnRMd4jGxG4byA3cVxBWupE+qcZabqtcWcIjmWIFksvRqFCHZFZj
# 9KLy46c1I5jG6G99jr8jOJYxupmLBvWo4VwAxAm10rAn2473+axyExaKtqR5DP1H
# 8kjmUoEtto2v/l2XK0SpxIfNYEYvbp0uRw5d6SmWEyp4q5kvFxRsL7R3rJcgxtll
# lHiFBfo9M5s/aNqwbKyvf5c3QjLI9xADuDdaYIYc5HDolgnDdyjzpefSDEljmAmB
# BqRYwDe5/dhCDgn8yoZ0gOWbAxyGHj+BA35G6dge2sHsD3WHV4xNXtF4A2v6n8Y6
# dD0qufDn1Q8C/zZzuQIDAQABo4IB1TCCAdEwDgYDVR0PAQH/BAQDAgeAMIGfBggr
# BgEFBQcBAQSBkjCBjzBMBggrBgEFBQcwAoZAaHR0cDovL3NlY3VyZS5nbG9iYWxz
# aWduLmNvbS9jYWNlcnQvZ3NnY2NyNDVldmNvZGVzaWduY2EyMDIwLmNydDA/Bggr
# BgEFBQcwAYYzaHR0cDovL29jc3AuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwMFUGA1UdIAROMEwwQQYJKwYBBAGgMgECMDQwMgYIKwYBBQUH
# AgEWJmh0dHBzOi8vd3d3Lmdsb2JhbHNpZ24uY29tL3JlcG9zaXRvcnkvMAcGBWeB
# DAEDMAkGA1UdEwQCMAAwRwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5nbG9i
# YWxzaWduLmNvbS9nc2djY3I0NWV2Y29kZXNpZ25jYTIwMjAuY3JsMB0GA1UdEQQW
# MBSBEmFkbWluQGN5YmVyYXJrLmNvbTATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNV
# HSMEGDAWgBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQUvfk3K3nY9zOK
# r24uYKcj/KTt+p8wDQYJKoZIhvcNAQELBQADggIBAB7REam0h5j/shCjeh87xdmt
# AvLf+bBp2STB6GVNs6nZixmLw4qjCWkFdeEBM5SG9HEpKQxCrmVAk9waH14pb7O7
# xrNeBcdsNMDZ3b3sjae63LodNC4kS+qPWGlIBG9giV3dbZjnTCW0zVI0WXWX6o5s
# vOs35FeLIAak8t8NsA3fJK0ngsBjOfO+2aJikZU4BaDy8Oj04TTAvLeLe2wtuzt/
# W+dddwIVNys7VFs4dppNCtrzPK0pYYWIq17KHPtQ0yPp5EtxWQqBgEnDjdu1mDss
# 0I93shcUYmst3AqGVliQRJZHnE6Hk665IiN7S6QJ+UVoyxprVGC6+k21pCPiMTTr
# BtwvfEP00JB/CGG3/Q+yIoetCMv1jkg6Cso7KOAGQkfeVAucRgq61AfDjp7f8LwO
# dqLJhQvL6pJ0fLiGSlh6y9Rr0kG0DRHKmsLUYofs67oRLUT9T/RqFwYSTzU4eKxU
# TJurkigpkCbn55bYw+C5T0+gX1QI16K97E51wEnJ9jp6u+YenUy/OgGDGnUWLiMn
# 4M6L60ZOgUx8Bndk5UxPPgdYwn6R6iPaJhYe0TAB2mTD9qPPD4+NBzBMDHC25tvP
# +Si4LmDAxO1H35ifRREyPZ1OD08iWQDsjcHqtS4vntaRa9SNtwNE/4KJtBE1C+vC
# c3epnQA75eTfm9t3CdYEMYIZ5jCCGeICAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcG
# A1UEChMQR2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0Mg
# UjQ1IEVWIENvZGVTaWduaW5nIENBIDIwMjACDAJZP4AHVQPEmDE5fjANBglghkgB
# ZQMEAgEFAKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJ
# BDEiBCCyjj+StiDbEdcoNr8jPgQbpu7Lr+jyycWS1AgdpRXowjANBgkqhkiG9w0B
# AQEFAASCAgAlKSkTRCkB5mAMWIQHcDxuaBKRnYJ9DXKL8AzZyjJ6M/uGHIAYf8EU
# DmDq6Izgqh+rwD5Umf/bieCoU9+F6EnfXRqQVOn3xYXfEJHGuBhHK2v3vp5iHCTu
# rjDKu6HjbS9Rg7tZuyGP2T+A/MX4QUuETBlK2XFt0L5bIzBMYVTrJujYDvMIDMSv
# 9ZsVqrOcdHS7lmvyMTRKg7YmBQsOkWkKlk2818k3d+gRL6Wmi7YzDRboZJR+U1XB
# FYZzz7bZgaz/2Bc3S8gaqGinVEM37QMUuEIFz8SgsbW9i7fOc//0eAU3BjT5zYw/
# h64obXJn8yFS073HsmfI1fmsXC6OladRmfRLcvvoSrSDWhAibVKlPcaVT8cdXXgZ
# 5l62huoUsTlfyFalgxKJilmBhMCdBX8e173+KkSlIcBqe63UeeO/1ZW7iozr98DF
# Rc3XusoI9oqyxi/HrPECvygmCPgx6rIGvIl7Eju5ej+FeLy+B+14GBixQ8Kl1XRy
# 0nDYQfurMd/hLn8c2vnEakKAwE5aO/kzf4z9Pjy80kByPtL1sLy1JczeYjCiVxF7
# oWq47DXziHONcBuPqD4YdYxeyim1eFf7DcBWCcz1+g0qZW7QcSJliVRhgWWVgINv
# A1J0rBRBnIr90FCSjqPB3nMFWJjWsNj/z8wseQ6pe347uZpmj4vHzaGCFs0wghbJ
# BgorBgEEAYI3AwMBMYIWuTCCFrUGCSqGSIb3DQEHAqCCFqYwghaiAgEDMQ0wCwYJ
# YIZIAWUDBAIBMIHoBgsqhkiG9w0BCRABBKCB2ASB1TCB0gIBAQYLKwYBBAGgMgID
# AQIwMTANBglghkgBZQMEAgEFAAQgpGkniBefjloTotjIzIwgAhcICKoP6bAk9ry9
# kFGYB9gCFBSGqTNa1QJkHeLVPSDM66LZgY1bGA8yMDI1MDExNTEyNTAyNlowAwIB
# AaBhpF8wXTELMAkGA1UEBhMCQkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2Ex
# MzAxBgNVBAMMKkdsb2JhbHNpZ24gVFNBIGZvciBDb2RlU2lnbjEgLSBSNiAtIDIw
# MjMxMaCCElQwggZsMIIEVKADAgECAhABm+reyE1rj/dsOp8uASQWMA0GCSqGSIb3
# DQEBCwUAMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNh
# MTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAt
# IEc0MB4XDTIzMTEwNzE3MTM0MFoXDTM0MTIwOTE3MTM0MFowXTELMAkGA1UEBhMC
# QkUxGTAXBgNVBAoMEEdsb2JhbFNpZ24gbnYtc2ExMzAxBgNVBAMMKkdsb2JhbHNp
# Z24gVFNBIGZvciBDb2RlU2lnbjEgLSBSNiAtIDIwMjMxMTCCAaIwDQYJKoZIhvcN
# AQEBBQADggGPADCCAYoCggGBAOqEN1BoPJWFtUhUcZfzhHLJnYDTCNxZu7/LTZBp
# R4nlLNjxqGp+YDdJc5u4mLMU4O+Mk3AgtfUr12YFdT96hFCpUg/g1udv1Bw1LuAv
# KSSjjnclJ+C4831kdQyaQuXGneLYh3OL76CNl34WoMSyRs9gxs8PgVCA3U/p5Eai
# NKc+GMdrtLb7vtqpVn5/nF02PWM0IUvI0qMTGj4vUWh1+X/8cIQRZTMSs0ZlKISg
# M8CSne24H4lj0B57LFuwBPS9cmPOsDEhAQJqcrIiLO/rKjsQ1fGa9CaiLPxTAQR5
# I2lR012+c4TLm4OIbSDSIM6Bq2oiS3mQQuaCQq8D69TQ2oN6wy1I8c1FkbcRQd0X
# 70D8EqKywFmqVJdObcN63YaG1Ds3RzjoAzwxv0wze0Ps8ND/ZaafmD3SxrpZImwQ
# WBHFBMzoopiwHTPQ85Ud+O1xtAtB1WR5orxgLsN6yd5wNxIWPgKPXTgRsASJZ4ul
# LSDbuNb1nPUPvIi/JyzD+SCiwQIDAQABo4IBqDCCAaQwDgYDVR0PAQH/BAQDAgeA
# MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMB0GA1UdDgQWBBT5Tqu+uPhb/8LHA/RB
# 7pz41nR9PzBWBgNVHSAETzBNMAgGBmeBDAEEAjBBBgkrBgEEAaAyAR4wNDAyBggr
# BgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8w
# DAYDVR0TAQH/BAIwADCBkAYIKwYBBQUHAQEEgYMwgYAwOQYIKwYBBQUHMAGGLWh0
# dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2NhL2dzdHNhY2FzaGEzODRnNDBDBggr
# BgEFBQcwAoY3aHR0cDovL3NlY3VyZS5nbG9iYWxzaWduLmNvbS9jYWNlcnQvZ3N0
# c2FjYXNoYTM4NGc0LmNydDAfBgNVHSMEGDAWgBTqFsZp5+PLV0U5M6TwQL7Qw71l
# ljBBBgNVHR8EOjA4MDagNKAyhjBodHRwOi8vY3JsLmdsb2JhbHNpZ24uY29tL2Nh
# L2dzdHNhY2FzaGEzODRnNC5jcmwwDQYJKoZIhvcNAQELBQADggIBAJX0Z8+TmkOS
# gxd21iBVvIn/5F+y5RUat5cRQC4AQb7FPySgG0cHMwRMtLRi/8bu0wzCNKCUXDeY
# 60T4X/gnCgK+HtEkHSPLLxyrJ3qzqcUvDOTlkPAVJB6jFRn474PoT7toniNvfT0N
# cXBhMnxGbvKP0ZzoQ036g+H/xOA+/t5X3wZr82oGgWirDHwq949C/8BzadscpxZP
# JhlYc+2UXuQaohCCBzI7yp6/3Tl11LyLVD9+UJU0n5I5JFMYg1DUWy9mtHv+Wynr
# HsUF/aM9+6Gw8yt5D7FLrMOj2aPcLJwrI5b2eiq7rcVXtoS2Y7NgmBHsxtZmbyKD
# HIpYA/SP7JxO0N/uzmEh07WVVEk7IVE9oSOFksJb8nqUhJgKjyRWIooE+rSaiUg1
# +G/rgYYRU8CTezq01DTMYtY1YY6mUPuIdB7XMTUhHhG/q6NkU45U4nNmpPtmY+E3
# ycRr+yszixHDdJCBg8hPhsrdSpfbfpBQJaFh7IabNlIHyz5iVewzpuW4GvrdJC4M
# +TKJMWo1lf720f8Xiq4jCSshrmLu9+4357DJsxXtdpq3/ef+4WjeRMEKdOGVyFf7
# FOseWt+WdcVlGff01Y0hr2O26/TiF0aft9cHbmqdK/7p0nFO0r5PYtNJ1mBfQON2
# mSBE2Epcs10a2eKqv01ZABeeYGc6RxKgMIIGWTCCBEGgAwIBAgINAewckkDe/S5A
# XXxHdDANBgkqhkiG9w0BAQwFADBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3Qg
# Q0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2ln
# bjAeFw0xODA2MjAwMDAwMDBaFw0zNDEyMTAwMDAwMDBaMFsxCzAJBgNVBAYTAkJF
# MRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWdu
# IFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0MIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA8ALiMCP64BvhmnSzr3WDX6lHUsdhOmN8OSN5bXT8MeR0
# EhmW+s4nYluuB4on7lejxDXtszTHrMMM64BmbdEoSsEsu7lw8nKujPeZWl12rr9E
# qHxBJI6PusVP/zZBq6ct/XhOQ4j+kxkX2e4xz7yKO25qxIjw7pf23PMYoEuZHA6H
# pybhiMmg5ZninvScTD9dW+y279Jlz0ULVD2xVFMHi5luuFSZiqgxkjvyen38Dljf
# gWrhsGweZYIq1CHHlP5CljvxC7F/f0aYDoc9emXr0VapLr37WD21hfpTmU1bdO1y
# S6INgjcZDNCr6lrB7w/Vmbk/9E818ZwP0zcTUtklNO2W7/hn6gi+j0l6/5Cx1Pcp
# Fdf5DV3Wh0MedMRwKLSAe70qm7uE4Q6sbw25tfZtVv6KHQk+JA5nJsf8sg2glLCy
# lMx75mf+pliy1NhBEsFV/W6RxbuxTAhLntRCBm8bGNU26mSuzv31BebiZtAOBSGs
# sREGIxnk+wU0ROoIrp1JZxGLguWtWoanZv0zAwHemSX5cW7pnF0CTGA8zwKPAf1y
# 7pLxpxLeQhJN7Kkm5XcCrA5XDAnRYZ4miPzIsk3bZPBFn7rBP1Sj2HYClWxqjcoi
# XPYMBOMp+kuwHNM3dITZHWarNHOPHn18XpbWPRmwl+qMUJFtr1eGfhA3HWsaFN8C
# AwEAAaOCASkwggElMA4GA1UdDwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEA
# MB0GA1UdDgQWBBTqFsZp5+PLV0U5M6TwQL7Qw71lljAfBgNVHSMEGDAWgBSubAWj
# kxPioufi1xzWx/B/yGdToDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0
# dHA6Ly9vY3NwMi5nbG9iYWxzaWduLmNvbS9yb290cjYwNgYDVR0fBC8wLTAroCmg
# J4YlaHR0cDovL2NybC5nbG9iYWxzaWduLmNvbS9yb290LXI2LmNybDBHBgNVHSAE
# QDA+MDwGBFUdIAAwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cuZ2xvYmFsc2ln
# bi5jb20vcmVwb3NpdG9yeS8wDQYJKoZIhvcNAQEMBQADggIBAH/iiNlXZytCX4Gn
# CQu6xLsoGFbWTL/bGwdwxvsLCa0AOmAzHznGFmsZQEklCB7km/fWpA2PHpbyhqIX
# 3kG/T+G8q83uwCOMxoX+SxUk+RhE7B/CpKzQss/swlZlHb1/9t6CyLefYdO1RkiY
# lwJnehaVSttixtCzAsw0SEVV3ezpSp9eFO1yEHF2cNIPlvPqN1eUkRiv3I2ZOBlY
# wqmhfqJuFSbqtPl/KufnSGRpL9KaoXL29yRLdFp9coY1swJXH4uc/LusTN763lNM
# g/0SsbZJVU91naxvSsguarnKiMMSME6yCHOfXqHWmc7pfUuWLMwWaxjN5Fk3hgks
# 4kXWss1ugnWl2o0et1sviC49ffHykTAFnM57fKDFrK9RBvARxx0wxVFWYOh8lT0i
# 49UKJFMnl4D6SIknLHniPOWbHuOqhIKJPsBK9SH+YhDtHTD89szqSCd8i3VCf2vL
# 86VrlR8EWDQKie2CUOTRe6jJ5r5IqitV2Y23JSAOG1Gg1GOqg+pscmFKyfpDxMZX
# xZ22PLCLsLkcMe+97xTYFEBsIB3CLegLxo1tjLZx7VIh/j72n585Gq6s0i96ILH0
# rKod4i0UnfqWah3GPMrz2Ry/U02kR1l8lcRDQfkl4iwQfoH5DZSnffK1CfXYYHJA
# UJUg1ENEvvqglecgWbZ4xqRqqiKbMIIFgzCCA2ugAwIBAgIORea7A4Mzw4VlSOb/
# RVEwDQYJKoZIhvcNAQEMBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENB
# IC0gUjYxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24w
# HhcNMTQxMjEwMDAwMDAwWhcNMzQxMjEwMDAwMDAwWjBMMSAwHgYDVQQLExdHbG9i
# YWxTaWduIFJvb3QgQ0EgLSBSNjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UE
# AxMKR2xvYmFsU2lnbjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJUH
# 6HPKZvnsFMp7PPcNCPG0RQssgrRIxutbPK6DuEGSMxSkb3/pKszGsIhrxbaJ0cay
# /xTOURQh7ErdG1rG1ofuTToVBu1kZguSgMpE3nOUTvOniX9PeGMIyBJQbUJmL025
# eShNUhqKGoC3GYEOfsSKvGRMIRxDaNc9PIrFsmbVkJq3MQbFvuJtMgamHvm566qj
# uL++gmNQ0PAYid/kD3n16qIfKtJwLnvnvJO7bVPiSHyMEAc4/2ayd2F+4OqMPKq0
# pPbzlUoSB239jLKJz9CgYXfIWHSw1CM69106yqLbnQneXUQtkPGBzVeS+n68UARj
# NN9rkxi+azayOeSsJDa38O+2HBNXk7besvjihbdzorg1qkXy4J02oW9UivFyVm4u
# iMVRQkQVlO6jxTiWm05OWgtH8wY2SXcwvHE35absIQh1/OZhFj931dmRl4QKbNQC
# TXTAFO39OfuD8l4UoQSwC+n+7o/hbguyCLNhZglqsQY6ZZZZwPA1/cnaKI0aEYdw
# gQqomnUdnjqGBQCe24DWJfncBZ4nWUx2OVvq+aWh2IMP0f/fMBH5hc8zSPXKbWQU
# LHpYT9NLCEnFlWQaYw55PfWzjMpYrZxCRXluDocZXFSxZba/jJvcE+kNb7gu3Gdu
# yYsRtYQUigAZcIN5kZeR1BonvzceMgfYFGM8KEyvAgMBAAGjYzBhMA4GA1UdDwEB
# /wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSubAWjkxPioufi1xzW
# x/B/yGdToDAfBgNVHSMEGDAWgBSubAWjkxPioufi1xzWx/B/yGdToDANBgkqhkiG
# 9w0BAQwFAAOCAgEAgyXt6NH9lVLNnsAEoJFp5lzQhN7craJP6Ed41mWYqVuoPId8
# AorRbrcWc+ZfwFSY1XS+wc3iEZGtIxg93eFyRJa0lV7Ae46ZeBZDE1ZXs6KzO7V3
# 3EByrKPrmzU+sQghoefEQzd5Mr6155wsTLxDKZmOMNOsIeDjHfrYBzN2VAAiKrlN
# IC5waNrlU/yDXNOd8v9EDERm8tLjvUYAGm0CuiVdjaExUd1URhxN25mW7xocBFym
# Fe944Hn+Xds+qkxV/ZoVqW/hpvvfcDDpw+5CRu3CkwWJ+n1jez/QcYF8AOiYrg54
# NMMl+68KnyBr3TsTjxKM4kEaSHpzoHdpx7Zcf4LIHv5YGygrqGytXm3ABdJ7t+uA
# /iU3/gKbaKxCXcPu9czc8FB10jZpnOZ7BN9uBmm23goJSFmH63sUYHpkqmlD75HH
# TOwY3WzvUy2MmeFe8nI+z1TIvWfspA9MRf/TuTAjB0yPEL+GltmZWrSZVxykzLsV
# iVO6LAUP5MSeGbEYNNVMnbrt9x+vJJUEeKgDu+6B5dpffItKoZB0JaezPkvILFa9
# x8jvOOJckvB595yEunQtYQEgfn7R8k8HWV+LLUNS60YMlOH1Zkd5d9VUWx+tJDfL
# RVpOoERIyNiwmcUVhAn21klJwGW45hpxbqCo8YLoRT5s1gLXCmeDBVrJpBAxggNJ
# MIIDRQIBATBvMFsxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52
# LXNhMTEwLwYDVQQDEyhHbG9iYWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4
# NCAtIEc0AhABm+reyE1rj/dsOp8uASQWMAsGCWCGSAFlAwQCAaCCAS0wGgYJKoZI
# hvcNAQkDMQ0GCyqGSIb3DQEJEAEEMCsGCSqGSIb3DQEJNDEeMBwwCwYJYIZIAWUD
# BAIBoQ0GCSqGSIb3DQEBCwUAMC8GCSqGSIb3DQEJBDEiBCBsLjR9KbyT9lH9rg1y
# +lxO1O0K1FQErkwTTFifrVcnYDCBsAYLKoZIhvcNAQkQAi8xgaAwgZ0wgZowgZcE
# IDqIepUbXrkqXuFPbLt2gjelRdAQW/BFEb3iX4KpFtHoMHMwX6RdMFsxCzAJBgNV
# BAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMTEwLwYDVQQDEyhHbG9i
# YWxTaWduIFRpbWVzdGFtcGluZyBDQSAtIFNIQTM4NCAtIEc0AhABm+reyE1rj/ds
# Op8uASQWMA0GCSqGSIb3DQEBCwUABIIBgLbHfOIezh9kKTk7ljg7+OqV/Ocvikwr
# SkvjEdNM9S1WwlA60HaY2y37gI8hLco1zwaudP1czMR+h+d1oLhLAOWuJ8bJvoTx
# kZ4Pzw0ePWzOKLwyn66yz6MT2hrDki0oU7FgIcIFXffQlUEpz9Yi9g9Tw20+DBFM
# XU8Piwy7w3MtjBdwAFd6pHjacy3LP54vd2cbGBuzerJ7lwhy3/XbLEsU+ybpxtN3
# I6I8apG5AhUqrytSI9Cgy3i9C3P+ecGL47EAPfswNyHCxZ+1zEWkzUzcXsU3+pN4
# ZzgqDYH54W77ToSVTBmt2ZzWS4WdmtUric6Vdc4+h4eJuXUyNRTJ9NaH1iQMiZ/U
# u6H8fAWToN1jDAYT5awNxHiTQ5jPi1brWmyECnJbIKzAZLChuppcd9woEgXCGGM5
# 45K/J2I0xX4yZDSoAtVayRWvG7RLXyZUTVofAymGaAbuCB/U3JSyQR+PvK7op0rj
# 4in5i7E3TzXKnHOVWU/viBKQxsqyFkYh+g==
# SIG # End signature block
