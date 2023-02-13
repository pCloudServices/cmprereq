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
  .PARAMETER POC
  .PARAMETER Troubleshooting
  .PARAMETER SkipVersionCheck
  .PARAMETER SkipIPCheck
 
  .EXAMPLE 
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1
  
  .EXAMPLE - Run checks if machine is out of domain
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -OutOfDomain

  .EXAMPLE - Troubleshoot certain components
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -Troubleshooting
  
  .EXAMPLE - Run in POC mode
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -POC

  .EXAMPLE - Skip Online Checks
  PS C:\> .\ConnectorCheckPrerequisites_PrivilegeCloud.ps1 -SkipVersionCheck -SkipIPCheck
  
#>
[CmdletBinding(DefaultParameterSetName="Regular")]
param(
	# Use this switch to Exclude the Domain user check
	[Parameter(ParameterSetName='Regular',Mandatory=$false)]
	[switch]$OutOfDomain,
	# Use this switch to run an additional tests for POC
	[Parameter(ParameterSetName='Regular',Mandatory=$false)]
	[switch]$POC,
	# Use this switch to troubleshoot specific items
	[Parameter(ParameterSetName='Troubleshoot',Mandatory=$false)]
	[switch]$Troubleshooting,
	# Use this switch to check CPM Install Connection Test
	[Parameter(ParameterSetName='CPMConnectionTest',Mandatory=$false)]
	[switch]$CPMConnectionTest,
    # Use this switch to skip online checks
    [Parameter(ParameterSetName='regular',Mandatory=$false)]
    [switch]$SkipVersionCheck,
    [Parameter(ParameterSetName='regular',Mandatory=$false)]
    [switch]$SkipIPCheck,
    [Parameter(ParameterSetName='regular',Mandatory=$false)]
    [switch]$DisableNLA,
    [Parameter(ParameterSetName='regular',Mandatory=$false)]
    [switch]$InstallRDS
)

# ------ SET Script Prerequisites ------
##############################################################

## Force Output to be UTF8 (for OS with different languages)
$OutputEncoding = [Console]::InputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding

## List of checks to be performed on POC
$arrCheckPrerequisitesPOC = @("CheckTLS1")

## List of checks to be excluded when machine is out of domain
$arrCheckPrerequisitesOutOfDomain = @("DomainUser","PrimaryDNSSuffix","remoteAppDomainUserPermissions") #PSM

## List of checks to be performed on every run of the script
$arrCheckPrerequisitesGeneral = @(
"VaultConnectivity", #General
"CustomerPortalConnectivity", #General
"OSVersion", #General
"Processors", #General
"Memory", #General
"InterActiveLoginSmartCardIsDisabled", #General
"UsersLoggedOn", #General
#"KBs", #Obsolete
"IPV6", #General
"MachineNameCharLimit", #General
#"NetworkAdapter", #General
"DotNet", #General
#"PSRemoting", #General
#"WinRM", #General
#"WinRMListener", #General
#"NoPSCustomProfile", #General
"PendingRestart", #General
"CheckNoProxy",
"GPO" #General + PSM
)

$arrCheckPrerequisitesSecureTunnel = @(
"TunnelConnectivity", #SecureTunnel
"ConsoleNETConnectivity", #SecureTunnel
"ConsoleHTTPConnectivity", #SecureTunnel
"SecureTunnelLocalPort" #SecureTunnel
)


$arrCheckPrerequisitesPSM = @(
#"CheckNoRDS", #PSM
"SQLServerPermissions", #PSM
"SecondaryLogon", #PSM
"KUsrInitDELL" #PSM
)

$arrCheckPrerequisitesCPM = @(
"CRLConnectivity" #CPM
)

# TBA next version
$arrCheckIdentityPrerequisites = @(
"IdentityIdaptiveApp", #Identity
"IdentityTruste", #Identity
"IdentityVerisign", #Identity
"IdentityGlobalSign" #Identity
)


## If not OutOfDomain then include domain related checks
If (-not $OutOfDomain){
	$arrCheckPrerequisitesPSM += $arrCheckPrerequisitesOutOfDomain
}
## Combine Checks from POC with regular checks
If ($POC){
	$arrCheckPrerequisitesGeneral += $arrCheckPrerequisitesPOC
}

$arrCheckPrerequisites = @{General = $arrCheckPrerequisitesGeneral},@{CPM = $arrCheckPrerequisitesCPM},@{PSM = $arrCheckPrerequisitesPSM},@{SecureTunnel = $arrCheckPrerequisitesSecureTunnel}#,@{IdentityISPSS = $arrCheckIdentityPrerequisites}


## List of GPOs to check
$arrGPO = @(
       [pscustomobject]@{Name='Require user authentication for remote connections by using Network Level Authentication';Expected='Not Configured'}
	   [pscustomobject]@{Name='Select RDP transport protocols'; Expected='Not Configured'}	
       [pscustomobject]@{Name='Use the specified Remote Desktop license servers'; Expected='Not Configured'}   
	   [pscustomobject]@{Name='Set client connection encryption level'; Expected='Not Configured'}
	   [pscustomobject]@{Name='Use Remote Desktop Easy Print printer driver first'; Expected='Not Configured'}
       [pscustomobject]@{Name='Allow CredSSP authentication'; Expected='Not Configured'}
       [pscustomobject]@{Name='Allow remote server management through WinRM'; Expected='Not Configured'}
       [pscustomobject]@{Name='Prevent running First Run wizard'; Expected='Not Configured'}
       [pscustomobject]@{Name='Allow Remote Shell Access'; Expected='Not Configured'}
       [pscustomobject]@{Name='Interactive logon: Require Smart card'; Expected='Not Configured'}
   )


##############################################################

# Get Script Location 
$ScriptLocation = Split-Path -Parent $MyInvocation.MyCommand.Path
# Get Debug / Verbose parameters for Script
$global:InDebug = $PSBoundParameters.Debug.IsPresent
$global:InVerbose = $PSBoundParameters.Verbose.IsPresent
$global:PSMConfigFile = "_ConnectorCheckPrerequisites_PrivilegeCloud.ini"

# Script Version
[int]$versionNumber = "13"

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

# ------ SET Schedule Task Parameters ------
$global:TriggerAtStart = New-ScheduledTaskTrigger -AtStartup
$global:TriggerAtLogon = New-ScheduledTaskTrigger -AtLogon
$global:ActionNLA = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -ExecutionPolicy Unrestricted -File `"$ScriptLocation\$g_ScriptName`" `"-skipIPCheck`" `"-skipVersionCheck`" `"-DisableNLA`""
$global:ActionRDS = New-ScheduledTaskAction -Execute "Powershell.exe" -Argument "-NoProfile -NoExit -ExecutionPolicy Unrestricted -File `"$ScriptLocation\$g_ScriptName`" `"-skipIPCheck`" `"-skipVersionCheck`" `"-InstallRDS`""
$global:taskNameNLA = "DisableNLAafterRDSInstall"
$global:taskNameRDS = "CompleteRDSInstallAfterRestart"
$global:taskDescrNLA = "DisableNLAafterRDSInstall"
$global:taskDescrRDS = "CompleteRDSInstallAfterRestart"
$global:taskNameDisableNLA = "DisableNLAafterRDSInstall"
$global:taskNameDisableRDS = "CompleteRDSInstallAfterRestart"

$global:table = ""
$SEPARATE_LINE = "------------------------------------------------------------------------" 
$g_SKIP = "SKIP"


#region Troubleshooting
Function Show-Menu{
    Clear-Host
    Write-Host "================ Troubleshooting Guide ================"
    
    Write-Host "1: Press '1' to Disable IPv6" -ForegroundColor Green
    Write-Host "2: Press '2' to Enable SecondaryLogon Service" -ForegroundColor Green
    Write-Host "3: Press '3' to Run CPM Install Connection Test" -ForegroundColor Green
    Write-Host "4: Press '4' to Retry Install RDS" -ForegroundColor Green
    Write-Host "4: Press '5' to Verify InstallerUser status" -ForegroundColor Green
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
	
		#PlatformParams
		$BasePlatformURL = "https://$portalSubDomainURL.cyberark.cloud"
		Write-LogMessage -type Info -MSG "Portal URL set: $BasePlatformURL" -Early
		#Platform Identity API
		$IdentityBaseURL = Invoke-WebRequest $BasePlatformURL -MaximumRedirection 0 -ErrorAction SilentlyContinue
		$IdentityHeaderURL = ([System.Uri]$IdentityBaseURL.headers.Location).Host
		
		$IdaptiveBasePlatformURL = "https://$IdentityHeaderURL"
		Write-LogMessage -type Info -MSG "Identity URL set: $IdaptiveBasePlatformURL" -Early
		$IdaptiveBasePlatformSecURL = "$IdaptiveBasePlatformURL/Security"
		$startPlatformAPIAuth = "$IdaptiveBasePlatformSecURL/StartAuthentication"
		$startPlatformAPIAdvancedAuth = "$IdaptiveBasePlatformSecURL/AdvanceAuthentication"
		$LogoffPlatform = "$IdaptiveBasePlatformSecURL/logout"
		$creds = Get-Credential -Message "Enter Privilege Cloud InstallerUser Credentials"
		if($($creds.GetNetworkCredential().Password) -match ' '){
			Write-Host "Your password has a space in it. We would fix it, but you may end up pasting it somewhere and wonder why it doesn't work :)" -ForegroundColor Yellow
			Write-Host "Remove it and try again." -ForegroundColor Yellow
			Pause
			Exit
		}

		#Begin Start Authentication Process
		Write-LogMessage -type Info -MSG "Begin Start Authentication Process" -Early
		$startPlatformAPIBody = @{TenantId = $IdentityTenantId; User = $creds.UserName ; Version = "1.0"} | ConvertTo-Json -Compress
		$IdaptiveResponse = Invoke-RestMethod -Uri $startPlatformAPIAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIBody -TimeoutSec 30
		$IdaptiveResponse.Result.Challenges.mechanisms
		
		#Begin Advanced Authentication Process
		Write-LogMessage -type Info -MSG "Begin Advanced Authentication Process" -Early
		$startPlatformAPIAdvancedAuthBody = @{SessionId = $($IdaptiveResponse.Result.SessionId); MechanismId = $($IdaptiveResponse.Result.Challenges.mechanisms.MechanismId); Action = "Answer"; Answer = $creds.GetNetworkCredential().Password } | ConvertTo-Json -Compress
		$AnswerToResponse = Invoke-RestMethod -Uri $startPlatformAPIAdvancedAuth -Method Post -ContentType "application/json" -Body $startPlatformAPIAdvancedAuthBody -TimeoutSec 30
		$AnswerToResponse.Result
	
		if($AnswerToResponse.Result.Summary -eq "LoginSuccess"){
			Write-Host "Success!" -ForegroundColor Green
			#LogOff
			Write-LogMessage -type Info -MSG "Begin Logoff Process" -Early
			$logoff = Invoke-RestMethod -Uri $LogoffPlatform -Method Post -Headers $IdentityHeaders
		}Else{
			Write-Host "Failed!" -ForegroundColor Red
				if($IdaptiveResponse.Result.Challenges.mechanisms.AnswerType.Count -gt 1){
					Write-LogMessage -type Info -MSG "Challenge mechanisms greater than one:" -Early
					$IdaptiveResponse.Result.Challenges.mechanisms.AnswerType
					Write-LogMessage -type Warning -MSG "Hint: Looks like MFA is enabled, make sure it's disabled."
				}
			}
	
	}catch
	{
		Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $($_.ErrorDetails.Message))"
	}
		#### Check against PVWA Directly, sometimes the shadowuser can be suspended/disabled in the vault but will be fine in identity. ####

			Write-LogMessage -type Info -MSG "Also testing directly against Privilege Cloud API." -Early
			Start-Sleep 3
			$basePVWA = "https://$portalSubDomainURL.privilegecloud.cyberark.cloud"
			$pvwaLogoff = "$BasePlatformURL/api/passwordvault/Auth/logoff"
			# Login URL is still Identity base platform on purpose.
			$basePVWALoginCyberArk = "$BasePlatformURL/api/passwordvault/Auth/CyberArk/Logon"
			$pvwaLogonBody = @{ username = $creds.UserName; password = $creds.GetNetworkCredential().Password } | ConvertTo-Json -Compress
		# Login to PVWA
		Try{
			Write-LogMessage -type Info -MSG "Begin Login: $basePVWALoginCyberArk" -Early
			$pvwaLogonToken = Invoke-RestMethod -Method Post -Uri $basePVWALoginCyberArk -Body $pvwaLogonBody -ContentType "application/json" -TimeoutSec 2700 -ErrorVariable pvwaResp
			$pvwaLogonHeader = @{Authorization = $pvwaLogonToken }
		
			# Get current logged on user details:

			$getCurrentUser = Invoke-RestMethod -Uri "$basePVWA/passwordvault/WebServices/PIMServices.svc/User" -Method Get -Headers $pvwaLogonHeader -ContentType "application/json"
			Write-LogMessage -type Info -MSG "Getting current user details: `"$basePVWA/passwordvault/WebServices/PIMServices.svc/User`"" -Early
			if(($getCurrentUser.Disabled -eq "True") -or ($getCurrentUser.Suspended -eq "True")){
				Write-Host "Failed!" -ForegroundColor Red
				Write-Host "User is Suspended/Disabled in the Vault!" -ForegroundColor Yellow
				Write-Host "Hint: Perform `"Set Password`" and `"MFA Unlock`" from Identity Portal and try again." -ForegroundColor Yellow
			}
			else
			{
				$getCurrentUser
				Write-Host "Success!" -ForegroundColor Green
			}

			#logoff
			Write-LogMessage -type Info -MSG "Begin Logoff Process" -Early
			$logoff = Invoke-RestMethod -Uri $pvwaLogoff -Method Post -Headers $pvwaLogonHeader
		}Catch
		{
			Write-LogMessage -Type Error -Msg "Error: $(Collect-ExceptionMessage $($_.ErrorDetails.Message))"
			#Lets check if identity was ok, then if vault is not, we know the pw is correct but user is most likely suspended/disabled.
			if(($AnswerToResponse.Result.Summary -eq "LoginSuccess") -and ($pvwaResp -like "*Authentication failure*")){
				Write-Host "Failed!" -ForegroundColor Red
				Write-Host "Hint: User is most likely Suspended/Disabled in the Vault" -ForegroundColor Yellow
				Write-Host "Hint: Perform `"Set Password`" and `"MFA Unlock`" from Identity Portal and try again." -ForegroundColor Yellow
			}
		}
	$creds = $null
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
            $errorMsg = "The logged in user domain: '$($env:userdnsdomain)' doesn't match the machine domain: '$PrimaryDNSSuffix'. Please see KB '000020063' on the customer support portal."
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
# Name...........: CheckTLS1
# Description....: Check If TLS1 is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function CheckTLS1
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting CheckTLS1..."
		$actual = ""
		$errorMsg = ""
		$result = $false
		
		if ($POC)
		{
			$TLS1ClientPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client"
			$TLS1ServerPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"
			ForEach ($tlsPath in @($TLS1ClientPath, $TLS1ServerPath))
			{
				$chkEnabled = $chkDisabledByDefault = $false
				If(Test-Path $tlsPath)
				{
					$chkEnabled = ((Get-ItemProperty $tlsPath).Enabled -eq 1)
					$chkDisabledByDefault = ((Get-ItemProperty $tlsPath).DisabledByDefault -eq 0)
				}
				If($chkEnabled -and $chkDisabledByDefault)
				{
					$actual = $true
					$result = $true
				}
				Else
				{
					$actual = $false
					$result = $false
					$errorMsg = "TLS 1.0 needs to be enabled for POC, if you don't know how to, rerun the script with -Troubleshooting flag"
					break
				}
			}
		}
		Write-LogMessage -Type Verbose -Msg "Finished CheckTLS1"
	} catch {
		$errorMsg = "Could not check if TLS is enabled. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = $True;
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
		$actual = (Get-WmiObject Win32_OperatingSystem).caption
		$errorMsg = ""
		$result = $false
		
		If($actual -Like '*2016*' -or $actual -like '*2019*')
		{
			$result = $true
		}
		elseif($actual -Like '*2012 R2*')
		{
			$errorMsg = "Privileged Cloud installation must be run on Windows Server 2016/2019."   
			$result = $false
		}
		elseif($actual -like '*2022*')
		{
			$errorMsg = "Detected OS 2022, only CPM can be installed on it. PSM is not yet supported."
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
		expected = "Windows Server 2016/2019";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: NetworkAdapter
# Description....: Check if all network adapters are Up
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function NetworkAdapter
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting NetworkAdapter..."
		$actual = ""
		$result = $false
		$errorMsg = ""

		$actual = (Get-NetAdapter | Where-Object status -ne "Up")
		if ($actual)
		{
			$errorMsg = "Not all NICs are up, the installer requires it (you can disable it again afterwards)."
			$actual = $true
		}
		else
		{
			$actual = $false
			$result = $true
		}
		Write-LogMessage -Type Verbose -Msg "Finished NetworkAdapter"
	} catch {
		$errorMsg = "Could not get Network Adapter Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "False";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}


# @FUNCTION@ ======================================================================================================================
# Name...........: IPv6
# Description....: Check if IPv6 is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function IPV6
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting IPv6..."
		$actual = ""
		$result = $false
		$errorMsg = ""
	
		$arrInterfaces = (Get-WmiObject -class Win32_NetworkAdapterConfiguration -filter "ipenabled = TRUE").IPAddress
		$IPv6Status = ($arrInterfaces | Where-Object { $_.contains("::") }).Count -gt 0

		if($IPv6Status)
		{
			$actual = "Enabled"
			$result = $false
            $errorMsg = "Disable IPv6, You can rerun the script with -Troubleshooting flag to do it."
		}
		else 
		{
			$actual = "Disabled"
			$result = $true
		}
		
		Write-LogMessage -Type Verbose -Msg "Finished IPv6"
	} catch {
		$errorMsg = "Could not get IPv6 Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "Disabled";
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
# Name...........: PSRemoting
# Description....: Check if PSRemoting is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function PSRemoting
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting PSRemoting..."
		$actual = ""	
		$result = $false
		$errorMsg = ""
		If($(Test-WSMan -ComputerName "localhost" -ErrorAction SilentlyContinue))
		{
			try 
			{
				Invoke-Command -ComputerName $env:COMPUTERNAME -ScriptBlock { ; } -ErrorAction Stop | out-null
				$actual = "Enabled"	
				$result = $true
			} 
			catch 
			{
				$actual = "Disabled"
				$result = $false
				
				$UserMemberOfProtectedGroup = $(Get-UserPrincipal).GetGroups().Name -match "Protected Users"
				if ($UserMemberOfProtectedGroup)
				{
					$errorMsg = "Current user was detected in 'Protected Users' group in AD, remove from group."
				}
				else
				{
					$errorMsg = "Could not connect using PSRemoting to $($env:COMPUTERNAME), Error: $(Collect-ExceptionMessage $_.exception.Message)"
				}
			}
		} Else {
			$actual = "Disabled"
			$result = $false
			$errorMsg = "Run 'winrm quickconfig' to analyze root cause"
		}
		Write-LogMessage -Type Verbose -Msg "Finished PSRemoting"	
	} catch {
		$errorMsg = "Could not get PSRemoting Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "Enabled";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: WinRM
# Description....: Check if WinRM is enabled or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function WinRM
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting WinRM..."
		$actual = ""	
		$result = $false
		$errorMsg = ""
		$WinRMService = (Get-Service winrm).Status -eq "Running"
		Start-sleep 1

		if ($WinRMService)
		{
				#Force the output to be in English in case this is ran on non EN OS.
                [Threading.Thread]::CurrentThread.CurrentUICulture = 'en-US'
                [CultureInfo]::CurrentUICulture = 'en-US'
			if ($getCRredSSP = ((Get-WSManCredSSP) -like "*This computer is not configured*"))
			{
				try {
					Enable-WSManCredSSP -Role Server -Force  | Out-Null
				} catch {
					if ($_.Exception.Message -like "*The config setting CredSSP cannot be changed because is controlled by policies*")
					{
						$errorMsg = "Can't Enable-WSManCredSSP, enforced by GPO."
					}
					Else
					{
						$errorMsg = $_.Exception.Message
					}
					$actual = $false
					$result = $actual
			   }
			}
			else
			{
			   $actual = (Get-Item -Path "WSMan:\localhost\Service\Auth\CredSSP").Value
			   if ($actual -eq $true){$result = "True"}
			}
		}
		else 
		{
			$errorMsg = "Verify WinRM service is running"
		}
	
		Write-LogMessage -Type Verbose -Msg "Finished WinRM"	
	} catch {
		$errorMsg = "Could not get WinRM Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "True";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: WinRMListener
# Description....: Check if WinRM is listening on the correct protocal and port
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function WinRMListener
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting WinRMListener..."
		$actual = ""
		$result = $false
		$errorMsg = ""

        $winrmListen = Get-WSManInstance -ResourceURI winrm/config/listener -SelectorSet @{address="*";Transport="HTTPS"} -ErrorAction Stop
		if ($winrmListen.Transport -eq "HTTPS" -and $winrmListen.Enabled -eq "true")
		{
              #Get Cert permissions
              $getWinRMCertThumb = Get-ChildItem Cert:\LocalMachine\My | Where-Object {$_.Thumbprint -eq ($winrmListen.CertificateThumbprint)}
              $rsaCert = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($getWinRMCertThumb)
              $filename = $rsaCert.key.uniquename

              #Check where Key is stored since it can be in two places
              if (Test-Path -Path "$g_CryptoPath\Keys\$filename"){
              $certkeypath = "$g_CryptoPath\Keys\$filename"}
              else{
              $certkeypath = "$g_CryptoPath\RSA\MachineKeys\$Filename"
              }
              $certPermissions =  Get-Acl -Path $certkeypath
              If ($certPermissions.Access.IdentityReference -contains "NT AUTHORITY\NETWORK SERVICE")
              {
			  $actual = $true
			  $result = $True
              }
              Else
              {
              $actual = "Empty"
			  $result = $false
			  $errorMsg = "WinRM HTTPS Cert doesn't have correct permissions (NETWORK SERVICE user needs 'read' permission, adjust this manually, if you don't know how, rerun the script with -Troubleshooting flag and select 'WinRMListenerPermissions'"
              }
            #Add Another IF, after successful check for HTTPs, check the thumbprint of the cert, and see if NETWORK SERVICE user has access to it (just read permission).
		} 
		else 
		{
			  $actual = "Empty"
			  $result = $false
			  $errorMsg = "WinRM Listener isn't receiving on HTTPS, check it with the following command 'Winrm e winrm/config/listener' in ps"
		}

		Write-LogMessage -Type Verbose -Msg "Finished WinRMListener"
	} catch {
        $errorMsg = "WinRM Listener isn't receiving on HTTPS, check it with the following command 'Winrm e winrm/config/listener' in ps, you can also rerun the script with -Troubleshooting flag to configure it"
		#$errorMsg = "Could not check WinRM Listener Port. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = $True;
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: NoPSCustomProfile
# Description....: Check if there is no PowerShell custom profile
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
function NoPSCustomProfile
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting NoPSCustomProfile..."
		$actual = ""
		$errorMsg = ""
		$result = $true

		$profileTypes = "AllUsersAllHosts","AllUsersCurrentHost","CurrentUserAllHosts","CurrentUserCurrentHost"

		ForEach($profiles in $profileTypes)
		{
			if (Test-Path -Path $profile.$profiles)
			{
				$errorMsg = "Custom powershell profile detected, unload it from Windows and restart PS instance."
				$result = $false
				break
			}
		}
		Write-LogMessage -Type Verbose -Msg "Finished NoPSCustomProfile"	
	} catch {
		$errorMsg = "Could not get PowerShell custom profile Status. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "False";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: KBs
# Description....: Check if all relevant KBs are installed
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function KBs
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting KBs..."
		$actual = ""
		$errorMsg = ""
		$otherOS = $false
		$result = $false

		$hotFixes = ""
		$osVersion = [System.Environment]::OSVersion.Version
		
		if ($osVersion.Major -eq 10)
		{
			# currently there are no KBs to check on win 2016
			$hotFixes = ""
		}
		elseif (($osVersion.Major -eq 6) -And ($osVersion.Minor -eq 3) -And ($osVersion.Build -eq 9600))
		{
			$hotFixes = @('KB2919355','KB3154520')
		}
		else
		{
			$otherOS = $true
			$result = $true		
		}
		
		if (!$otherOS)
		{
			if($hotFixes -eq "")
			{
				$errorMsg = $g_SKIP
				$result =  $true
			}
		 
			else
			{
				$pcHotFixes = Get-HotFix $hotFixes -EA ignore | Select-Object -Property HotFixID 
		
				#none of the KBs installed
				if($null -eq $pcHotFixes)
				{
					$errorMsg = "KBs not installed: $hotFixes"
					$actual = "Not Installed"
					$result = $false
				}

				else
				{	
					$HotfixesNotInstalled = $hotFixes | Where-Object { $_ -notin $pcHotFixes }
		
					if($HotfixesNotInstalled.Count -gt 0)
					{			
						$errorMsg = "KBs not installed: $($HotfixesNotInstalled -join ',')"
						$actual = "Not Installed"
						$result = $false
					}
					else
					{
						$actual = "Installed"
						$result = $true
					}
				}
			}
		}

		Write-LogMessage -Type Verbose -Msg "Finished KBs"
	} catch {
		$errorMsg = "Could not get Installed KBs. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
	
	return [PsCustomObject]@{
		expected = "Installed";
		actual = $actual;
		errorMsg = $errorMsg;
		result = $result;
	}
}

# @FUNCTION@ ======================================================================================================================
# Name...........: ServerInDomain
# Description....: Check if the server is in Domain or not
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function ServerInDomain
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting ServerInDomain..."
		$result = $false
    
		if ((Get-WmiObject win32_computersystem).partofdomain) 
		{
			  $actual = "In Domain"
			  $result = $true
		} 
		else 
		{
			  $actual = "Not in Domain"
			  $result = $false
		}

		Write-LogMessage -Type Verbose -Msg "Finished ServerInDomain"
	} catch {
		$errorMsg = "Could not verify if server is in Domain. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
	return [PsCustomObject]@{
		expected = "In Domain";
		actual = $actual;
		errorMsg = "";
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
		$wmiClientUtilities = (Invoke-WmiMethod -Namespace "Root\CCM\ClientSDK" -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Ignore).RebootPending
		
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
		$wmiClientUtilities = (Invoke-WmiMethod -Namespace "Root\CCM\ClientSDK" -Class CCM_ClientUtilities -Name DetermineIfRebootPending -ErrorAction Ignore).RebootPending
		
		$chkComponentBasedServicing = ($null -ne $regComponentBasedServicing)
		$chkWindowsUpdate =	($null -ne $regWindowsUpdate)
		$chkSessionManager = ($null -ne $regSessionManager)
		$chkClientUtilities = ($null -ne $wmiClientUtilities)
		
		if ($chkComponentBasedServicing -or $chkWindowsUpdate -or $chkSessionManager -or $chkClientUtilities)
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
# Name...........: GPO
# Description....: Check the GPOs on the machine
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function GPO
{
	[OutputType([PsCustomObject])]
	param ()
	[int]$script:gpoRDSerrorsfound = 0
	try{
		Write-LogMessage -Type Verbose -Msg "Starting GPO..."
		$actual = ""	
		$errorMsg = ""
		$result = $false
		$gpoResult = $false
		$compatible = $true

		$path = "C:\Windows\temp\GPOReport.xml"
		gpresult /f /x $path *> $null

		[xml]$xml = Get-Content $path
		$RDSGPOs = $xml.Rsop.ComputerResults.ExtensionData.extension.policy | Where-Object { ($_.Category -match "Windows Components") }
		if($RDSGPOs.Category.Count -gt 0)
		{
			[int]$script:gpoRDSerrorsfound = 1
			ForEach($item in $RDSGPOs)
			{
				$skip = $false
				$name = "GPO: $($item.Name)"
				$errorMsg = ""	
				# Check if GPO exists in the critical GPO items
				If($arrGPO -match $item.name)
				{
					$expected = $($arrGPO -match $item.name).Expected
					$gpoResult = ($Expected -eq $($item.state))
					if(-not $gpoResult )
					{
						$compatible = $false
						$errorMsg = "Expected:"+$Expected+" Actual:"+$($item.state)
					}
				}
				# Check if GPO exists in RDS area
				elseif($item.Category -match "Remote Desktop Services")
				{
					$expected = 'Not Configured'
					$compatible = $false
					$errorMsg = "Expected:'Not Configured' Actual:"+$($item.state)
				}
				else {
					$skip = $true
				}
				if(!$skip)
				{
					Write-LogMessage -Type Verbose -Msg ("{0}; Expected: {1}; Actual: {2}" -f $name, $Expected, $item.state)
					$reportObj = @{expected = $expected; actual = $($item.state); errorMsg = $errorMsg; result = $gpoResult;}
					AddLineToTable $name $reportObj
				}
			}		
		}

		$errorMsg = $g_SKIP
		if(!$compatible)
		{
			 $actual = "Not Compatible"
			 $result = $false
		}
		else
		{
		   $result = $true
		}
	} catch {
		$errorMsg = "Could not check GPO settings on machine. Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		expected = "PSM Compatible";
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
	try{
		Write-LogMessage -Type Verbose -Msg "Starting ConsoleHTTPConnectivity..."
		$actual = ""
		$result = $false
		$errorMsg = ""
		
		$CustomerGenericGET = 0
		Try{
			$connectorConfigURL = "https://$g_ConsoleIP/connectorConfig/v1?customerId=$CustomerId&configItem=environmentFQDN"
			$CustomerGenericGET = Invoke-RestMethod -Uri $connectorConfigURL -TimeoutSec 20 -ContentType 'application/json'
			If($null -ne $CustomerGenericGET.config)
			{
				$actual = "200"
				$result = $true
			}
		} catch {
			if ($_.Exception.Message -eq "Unable to connect to the remote server")
			{
				$errorMsg = "Unable to connect to the remote server - Unable to GET to '$connectorConfigURL'"
				$result = $false
			}
			elseif ($_.Exception.Message -eq "The underlying connection was closed: An unexpected error occurred on a receive.")
			{
				$errorMsg = "The underlying connection was closed - Unable to GET to '$connectorConfigURL'"
				$result = $false
			}
            elseif ($_.Exception.Response.StatusCode.value__ -eq 404)
			{
				$actual = $true
				$result = $true
			}
			else
			{
				Throw $_
			}
		}		
		
		Write-LogMessage -Type Verbose -Msg "Finished ConsoleHTTPConnectivity"
	} catch {
		$errorMsg = "Could not verify console connectivity. Error: $(Collect-ExceptionMessage $_.Exception)"
	}
		
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
# Description....: Required SQL Server permissions
# Parameters.....: None
# Return Values..: Custom object (Expected, Actual, ErrorMsg, Result)
# =================================================================================================================================
Function SQLServerPermissions
{
	[OutputType([PsCustomObject])]
	param ()
	try{
		Write-LogMessage -Type Verbose -Msg "Starting SQLServerPermissions..."
		$actual = ""
		$result = $False
		$errorMsg = ""

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
	$errorMsg = ""
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
                     # if port 1858, indicating vault test, declate param so we can use it in CPMConnectionTest.
                     if($port -eq 1858){$script:VaultConnectivityOK = $True}
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
		$PublicIP | Out-File "$($env:COMPUTERNAME) PublicIP.txt"
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

		$CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
		$WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)

		if(($WindowsPrincipal.IsInRole("Domain Users") -eq $False) -or 
    	($WindowsPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator") -eq $False))
		{
			# NOT domain user with administrative rights
			$actual = $false
			$result = $False
			$errorMsg = "Installing user must be a member of `"Domain Users`" group and in the local administrators group (requires logout login to take affect)."
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
		$errorMsg = "Error: $(Collect-ExceptionMessage $_.Exception)"
	}

	return [PsCustomObject]@{
		actual = $actual;
		result = $result;
		errorMsg = $errorMsg;
		expected = $true;
	}
}

Function CheckNoProxyRDS()
{
	Write-LogMessage -Type info	-Msg "Checking if machine has proxy configuration..." -early
	if(-not($(netsh winhttp show proxy)) -match "Direct access")
	{
		Write-LogMessage -Type Warning -Msg "Proxy configuration detected, please disable and rerun script. Run `"netsh winhttp show proxy`" to disable run `"netsh winhttp reset proxy`""
		Pause
		Exit
	}
	Else
	{
		Write-LogMessage -Type info	-Msg "No proxy configured." -early
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
    New-RDSessionDeployment -ConnectionBroker ("$ConnectionBroker") -SessionHost ("$SessionHost") -WarningAction SilentlyContinue
}

function NewSessionCollection([string]$CollectionName, [string]$SessionHost, [string]$ConnectionBroker)
{
    Write-LogMessage -type Info -MSG "Creating RDS collection called $CollectionName" -Early
    New-RDSessionCollection -CollectionName $CollectionName -SessionHost ("$SessionHost") -ConnectionBroker ("$ConnectionBroker") -WarningAction SilentlyContinue
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

# can be removed later versions
import-module RemoteDesktop -Verbose:$false | Out-Null;


# @FUNCTION@ ======================================================================================================================
# Name...........: InstallRDS
# Description....: Installs RDS role on the machine.
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
function InstallRDS{
$script:CollectionName="PSM-RemoteApp"
$script:TerminalServicesKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\"
$script:RedirectClipboardValue = "fDisableClip"
$script:RedirectDrivesValue	= "fDisableCdm"

    # Get the details of the Remote Desktop Services rule
    Write-LogMessage -Type Info -Msg "Deploying RDS Roles" -Early
	
	# Check if machine has pending restarts.
	PendingRestartRDS
	
	# Check machine has no proxy configuration
	CheckNoProxyRDS
	
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
                SetScheduledTask -taskName $taskNameRDS -TriggerType $TriggerAtLogon -taskDescription $taskDescrRDS -action $actionRDS -AdminUsername $AdminUserName

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
					if ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain)
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
                    SetScheduledTask -taskName $taskNameRDS -TriggerType $TriggerAtLogon -taskDescription $taskDescrRDS -action $actionRDS -AdminUsername $AdminUserName
                    pause
                    Restart-Computer -Force
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

                        # Check if logged in user domain matches the machine domain, in cases where Primary DNS suffix is set, it will be different.
                        if($(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tcpip\Parameters | select -ExpandProperty Domain) -eq $env:userdnsdomain)
                        {
                            $cb="$env:computername.$env:userdnsdomain"
                        }
                        Else
                        {
                            $cb="$env:computername.$(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\tcpip\Parameters | select -ExpandProperty Domain)"
                        }
                        # Installing Remote Desktop Broker - Session Host
                        NewSessionDeployment ($cb) ($cb)
                        
                        # Configure the RDS Collection - remoteapp
                        NewSessionCollection ($CollectionName) ($cb) ($cb)

                        #disable NLA just in case it comes back.
                        Disable-NLA
                        		 				 
                        Write-LogMessage -type info -MSG "RDS Connection Broker was installed successfully"
                    }
			        catch
			        {
					    Write-LogMessage -type Error -MSG "Failed to install RDS Connection-Broker role"
			        }
                }
			    else
                {
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
    $disableNLA = (Get-WmiObject -Class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -ComputerName $env:COMPUTERNAME -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

    # Remove scheduled Task so we don't run it infinitely.
    UnsetScheduledTask -taskName $taskNameNLA
}


# @FUNCTION@ ======================================================================================================================
# Name...........: checkIfPSMisRequired
# Description....: Check if PSM will be installed on the machine, depending on answer, we will deploy RDS role.
# Parameters.....: None
# Return Values..: True/False
# =================================================================================================================================
function checkIfPSMisRequired()
{
    #Check if RDS/CB installed, 
    $RDSFeature = Get-WindowsFeature *Remote-Desktop-Services*
	$ConnectionBrokerFeature = Get-WindowsFeature *RDS-Connection-Broker*

    if(($RDSFeature.Installed -eq $false) -or ($ConnectionBrokerFeature.Installed -eq $false))
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
}


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
# Name...........: CPMConnectionTest
# Description....: Performs multiple Casos calls against a vault
# Parameters.....: UserName, Password, VaultIP
# Return Values..: stdout txt file
# =================================================================================================================================
Function CPMConnectionTest(){
#Static
$VaultOperationFolder = "$PSScriptRoot\VaultOperationsTester"
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
                Exit
            }
        }
        ElseIf($CPMConnectionTest)
        {
            #RunTheCheck
        }
        Else
        {
            Break
        }

    }
 #Prereqs   
 if(!(Test-Path -Path "$VaultOperationFolder\VaultOperationsTester.exe")){
     Write-LogMessage -Type Error -Msg "Required folder doesn't exist: `"$VaultOperationFolder`". Make sure you get the latest version and extract it correctly from zip. Rerun the script with -CPMConnectionTest flag."
     Pause
     Return
 }
 if((Get-WmiObject -Class win32_product | where {$_.Name -like "Microsoft Visual C++ 2013 x86*"}) -eq $null){
    $CpmRedis = "$VaultOperationFolder\vcredist_x86.exe"
    Write-LogMessage -type Info -MSG "Installing Redis++ x86 from $CpmRedis..." -Early
    Start-Process -FilePath $CpmRedis -ArgumentList "/install /passive /norestart" -Wait
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
                    [int]$lasthint = $lasthint+1
                    Write-LogMessage -type Warning -MSG "3) Hint: Communication over 1858/TCP is required to utilize sticky session and maintain the same source IP for the duration of the session."
                    Write-LogMessage -type Warning -MSG "4) In case of PA FW or similar configuration check out this page: "
                    Write-LogMessage -type Warning -MSG "   https://docs.cyberark.com/Product-Doc/OnlineHelp/PrivCloud-SS/Latest/en/Content/Privilege%20Cloud/Priv-Cloud-Firewall-setup.htm"
                }
                Else{
                    Write-LogMessage -type Warning -MSG "3) Hint: Typically this means there is a problem with Username/Password or FW configuration."
                }
                Write-LogMessage -type Warning -MSG "$lasthint) Rerun the script with -CPMConnectionTest flag."
            }
            Else{
                $stdout | Write-Host -ForegroundColor DarkGray
                Write-LogMessage -type Success -MSG "Connection is OK!"
                Write-LogMessage -type Success -MSG "If you want to rerun this check in the future, run the script with -CPMConnectionTest or -Troubleshooting."

            # Add entry to ini file that this test passed and skip it from now on.
            Remove-Item -Path $CONFIG_PARAMETERS_FILE
            Try{$parameters += @{CPMConnectionTestPassed = $True}}Catch{}
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
	[Parameter(ParameterSetName='Regular',Mandatory=$true, HelpMessage="Example: https://<customerDomain>.privilegecloud.cyberark.com")]
	[AllowEmptyString()]
	[Alias("PortalURL")]
	[ValidateScript({
		If(![string]::IsNullOrEmpty($_)) {
			($_ -like "*.privilegecloud.cyberark.com*") -or ($_ -like "*.cyberark.cloud*")
		}
		Else { $true }
	})]
	[String]${Please enter your provided portal URL Address (Or leave empty)},
	[Parameter(ParameterSetName='Regular',Mandatory=$true)]
	[AllowEmptyString()]
	[Alias("CustomerId")]
	[String]${Please enter your CustomerId (Or leave empty)},
	# Config File
	[Parameter(ParameterSetName='File',Mandatory=$true)]
	[ValidateScript({Test-Path $_})]
	[String]$ConfigFile
    
 )
	 If([string]::IsNullOrEmpty($ConfigFile))
	 {
        # ------ Copy parameter values entered ------
        $script:PortalURL = ${Please enter your provided portal URL Address (Or leave empty)}
        $script:CustomerId = ${Please enter your CustomerId (Or leave empty)}
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
            CustomerId = $CustomerId.trim()
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
        $script:CustomerId = $parameters.CustomerId
        # deal with ispss
        if($PortalURL -like "*.privilegecloud.cyberark.com"){$script:g_ConsoleIP = $g_ConsoleIPstd}else{$script:g_ConsoleIP = $g_ConsoleIPispss}
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
 
Function CheckPrerequisites()
{

	Try
	{
        $cnt = ($arrCheckPrerequisites.Values[0]+$arrCheckPrerequisites.Values[1]+$arrCheckPrerequisites.Values[2]+$arrCheckPrerequisites.Values[3]).Count
		Write-LogMessage -Type Info -SubHeader -Msg "Starting checking $cnt prerequisites..."
		
        $global:table = @()
        $errorCnt = 0
        $warnCnt = 0
        $table = ""

		ForEach ($methods in $arrCheckPrerequisites)
        {
            Write-LogMessage -Type Warning -Msg "< $($methods.Keys) Related Checks >"
            ForEach($method in $($methods.Values))
            {
                Try
                { 
                    Write-Progress -Activity "Checking $method..."
                    $resultObject = &$method  

                    if($null -eq $resultObject -or !$resultObject.result)
                    {
                        $errorCnt++
                    }

                    Write-Progress -Activity "$method completed" -Completed      
                }
                Catch
                {
                    $resultObject.errorMsg = $_.Exception.Message
                    $errorCnt++
                }

			    if($resultObject.errorMsg -ne $g_SKIP)
			    {
			    	AddLineToReport $method $resultObject
			    }
			    else
			    {
			    	# remove the skip description
			    	$resultObject.errorMsg = ""
			    }
			    
                AddLineToTable $method $resultObject
            }
        }
        
        Write-LogMessage -Type Info -Msg " " -Footer
		
        $errorStr = "";
        $warnStr = "";


        if($global:table.Count -gt 0)
        {       
            if($errorCnt -eq 1)
			{
				$errorStr = "failure"
			}
			else
			{
				$errorStr = "failures"
			}

			$warnCnt = $global:table.Count - $errorCnt

			if($warnCnt -eq 1)
			{
				$warnStr = "warning"
			}
			else
			{
				$warnStr = "warnings"
			}


			Write-LogMessage -Type Info -Msg "Checking Prerequisites completed with $errorCnt $errorStr and $warnCnt $warnStr"

            Write-LogMessage -Type Info -Msg "$SEPARATE_LINE"
            $global:table | Format-Table -Wrap
            #$global:table | Format-Table -Wrap -AutoSize

            Write-LogMessage -Type LogOnly -Msg $($global:table | Out-String)
        }
        else
        {
            Write-LogMessage -Type Success -Msg "Checking Prerequisites completed successfully"
        }

        Write-LogMessage -Type Info -Msg " " -Footer
	}
	Catch
	{
        Throw $(New-Object System.Exception ("CheckPrerequisites: Failed to run CheckPrerequisites",$_.Exception))
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
            $scriptPathAndArgs = "& `"$g_ScriptName`" -POC:$POC -OutOfDomain:$OutOfDomain -Troubleshooting:$Troubleshooting -InstallRDS:$InstallRDS -DisableNLA:$DisableNLA -skipVersionCheck:$SkipVersionCheck -SkipIPCheck:$SkipIPCheck"
			Write-LogMessage -Type Info -Msg "Finished Updating, please close window (Regular or ISE) and relaunch script."
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
Function Get-LogoHeader{
$t = @"
  ____      _                _         _    
 / ___|   _| |__   ___ _ __ / \   _ __| | __
| |  | | | | '_ \ / _ \ '__/ _ \ | '__| |/ /
| |__| |_| | |_) |  __/ | / ___ \| |  |   < 
 \____\__, |_.__/ \___|_|/_/   \_\_|  |_|\_\
      |___/ 

"@

for ($i=0;$i -lt $t.length;$i++) {
if ($i%2) {
 $c = "green"
}
elseif ($i%5) {
 $c = "black"
}
elseif ($i%7) {
 $c = "gray"
}
else {
   $c = "green"
}
write-host $t[$i] -NoNewline -ForegroundColor $c
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
            $PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:")).Host
            #Deal with TM format
            if($PortalURL -eq $null)
                {
                $PortalURL = ([System.Uri](Get-Content $ConnectionDetailsFile | Select-String -AllMatches "privilegecloud.cyberark.com").ToString().Trim("URL:").Trim()).OriginalString
                }
            if($PortalURL -match "https://")
	            {
		        $PortalURL = ([System.Uri]$PortalURL).Host
	            }
            $CustomerId = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "CustomerId:").ToString().ToLower().trim("customerid:").Trim()
            $VaultIP = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "VaultIp:").ToString().ToLower().trim("vaultip:").Trim()
            $TunnelIP = (Get-Content $ConnectionDetailsFile | Select-String -allmatches "ConnectorServerIp:").ToString().ToLower().trim("connectorserverip:").Trim()

            $parameters = @{
			    PortalURL = $PortalURL
			    VaultIP = $VaultIP
			    TunnelIP = $TunnelIP
                CustomerId = $CustomerId
		    }
		    $parameters | Export-CliXML -Path $CONFIG_PARAMETERS_FILE -NoClobber -Encoding ASCII
		    }
            ElseIf($PortalURL -match "https://")
	            {
		        $PortalURL = ([System.Uri]$PortalURL).Host
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
        # Main Pre-requisites check
		CheckPrerequisites

        # Install RDS on the Initial Run
        checkIfPSMisRequired

        # If VaultConnectivity passed, run CPM Test.
        if($VaultConnectivityOK -eq $true){CPMConnectionTest}
	} catch	{
		Write-LogMessage -Type Error -Msg "Checking prerequisites failed. Error(s): $(Collect-ExceptionMessage $_.Exception)"
	}
}
Write-LogMessage -Type Info -Msg "Script Ended" -Footer
Pause
###########################################################################################
# Main end
###########################################################################################

# SIG # Begin signature block
# MIIgTgYJKoZIhvcNAQcCoIIgPzCCIDsCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAKk79plwH5xQp5
# AqapSzf/jdxr55aFfJyDg13OoNDzWaCCDl8wggboMIIE0KADAgECAhB3vQ4Ft1kL
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
# EXIMiEQmM2YBRN/kMw4h3mKJSAfa9TCCB28wggVXoAMCAQICDHBNxPwWOpXgXVV8
# DDANBgkqhkiG9w0BAQsFADBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFs
# U2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVWIENvZGVT
# aWduaW5nIENBIDIwMjAwHhcNMjIwMjE1MTMzODM1WhcNMjUwMjE1MTMzODM1WjCB
# 1DEdMBsGA1UEDwwUUHJpdmF0ZSBPcmdhbml6YXRpb24xEjAQBgNVBAUTCTUxMjI5
# MTY0MjETMBEGCysGAQQBgjc8AgEDEwJJTDELMAkGA1UEBhMCSUwxEDAOBgNVBAgT
# B0NlbnRyYWwxFDASBgNVBAcTC1BldGFoIFRpa3ZhMRMwEQYDVQQJEwo5IEhhcHNh
# Z290MR8wHQYDVQQKExZDeWJlckFyayBTb2Z0d2FyZSBMdGQuMR8wHQYDVQQDExZD
# eWJlckFyayBTb2Z0d2FyZSBMdGQuMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEA8rPX6yAVM64+/qMQEttWp7FdAvq9UfgxBrW+R0NtuXhKnjV05zmIL6zi
# AS0TlNrQqu5ypmuagOWzYKDtIcWEDm6AuSK+QeZprW69c0XYRdIf8X/xNUawXLGe
# 5LG6ngs2uHGtch9lt2GLMRWILnKviS6l6F06HOAow+aIDcNGOukddypveFrqMEbP
# 7YKMekkB6c2/whdHzDQiW6V0K82Xp9XUexrbdnFpKWXLfQwkzjcG1xmSiHQUpkSH
# 4w2AzBzcs+Nidoon5FEIFXGS2b1CcCA8+Po5Dg7//vn2thirXtOqaC+fjP1pUG7m
# vrZQMg3lTHQA/LTL78R3UzzNb4I9dc8yualcYK155hRU3vZJ3/UtktAvDPC/ewoW
# thebG77NuKU8YI6l2lMg7jMFZ1//brICD0RGqhmPMK9MrB3elSuMLaO566Ihdrlp
# zmj4BRDCfPuH0QfwkrejsikGEMo0lErfHSjL3NaiE0PPoC4NW7nc6Wh4Va4e3VFF
# Z9zdnoTsCKJqk4s13MxBbjdLIkCcfknMSxAloOF9h6IhzWOylSROAy/TZfGL5kzQ
# qxzcIhdXLWHHWdbz4DD3qxYc6g1G3ZwgFPWf7VbKQU3FsAxgiJvmKPVeOfIN4iYT
# V4toilRR8KX/IaA1NMrN9EiA//ZhN3HONS/s6AxjjHJTR29GOQkCAwEAAaOCAbYw
# ggGyMA4GA1UdDwEB/wQEAwIHgDCBnwYIKwYBBQUHAQEEgZIwgY8wTAYIKwYBBQUH
# MAKGQGh0dHA6Ly9zZWN1cmUuZ2xvYmFsc2lnbi5jb20vY2FjZXJ0L2dzZ2NjcjQ1
# ZXZjb2Rlc2lnbmNhMjAyMC5jcnQwPwYIKwYBBQUHMAGGM2h0dHA6Ly9vY3NwLmds
# b2JhbHNpZ24uY29tL2dzZ2NjcjQ1ZXZjb2Rlc2lnbmNhMjAyMDBVBgNVHSAETjBM
# MEEGCSsGAQQBoDIBAjA0MDIGCCsGAQUFBwIBFiZodHRwczovL3d3dy5nbG9iYWxz
# aWduLmNvbS9yZXBvc2l0b3J5LzAHBgVngQwBAzAJBgNVHRMEAjAAMEcGA1UdHwRA
# MD4wPKA6oDiGNmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3NnY2NyNDVldmNv
# ZGVzaWduY2EyMDIwLmNybDATBgNVHSUEDDAKBggrBgEFBQcDAzAfBgNVHSMEGDAW
# gBQlndD8WQmGY8Xs87ETO1ccA5I2ETAdBgNVHQ4EFgQU0Vg7IAYAK18fI9dI1YKi
# WA0D1bEwDQYJKoZIhvcNAQELBQADggIBAFOdA15mFwRIM54PIL/BDZq9RU9IO+YO
# lAoAYTJHbiTY9ZqvA1isS6EtdYKJgdP/MyZoW7RZmcY5IDXvXFj70TWWvfdqW/Qc
# MMHtSqhiRb4L92LtR4lS+hWM2fptECpl9BKH28LBZemdKS0jryBEqyAmuEoFJNDk
# wxzQVKPksvapvmSYwPiBCtzPyHTRo5HnLBXpK/LUBJu8epAgKz6LoJjnrTIF4U8R
# owrtUC0I6f4uj+sKYE0iV3/TzwsTJsp7MQShoILPr1/75fQjU/7Pl2fbM++uAFBC
# sHQHYvar9KLslFPX4g+cDdtOHz5vId8QYZnhCduVgzUGvELmXXR1FYV7oJNnh3eY
# Xc5gm7vSNKlZB8l7Ls6h8icBV2zQbojDiH0JOD//ph62qvnMp8ev9mvhvLXRCIxc
# aU7CYI0gNVvg9LPi5j1/tswqBc9XAfHUG9ZYVxYCgvynEmnJ5TuEh6GesGRPbNIL
# l418MFn4EPQUqxB51SMihIcyqu6+3qOlco8Dsy1y0gC0Hcx+unDZPsN8k+rhueN2
# HXrPkAJ2bsEJd7adPy423FKbA7bRCOc6dWOFH1OGANfEG0Rjw9RfcsI84OkKpQ7R
# XldpKIcWuaYMlfYzsl+P8dJru+KgA8Vh7GTVb5USzFGeMyOMtyr1/L2bIyRVSiLL
# 8goMl4DTDOWeMYIRRTCCEUECAQEwbDBcMQswCQYDVQQGEwJCRTEZMBcGA1UEChMQ
# R2xvYmFsU2lnbiBudi1zYTEyMDAGA1UEAxMpR2xvYmFsU2lnbiBHQ0MgUjQ1IEVW
# IENvZGVTaWduaW5nIENBIDIwMjACDHBNxPwWOpXgXVV8DDANBglghkgBZQMEAgEF
# AKB8MBAGCisGAQQBgjcCAQwxAjAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCBL
# JNm8cBoWDdpveJkF0KJHP7EZdURfleupOYirxIgdCjANBgkqhkiG9w0BAQEFAASC
# AgBaSTerJZWrsM4X8Lcd2ORaONOHVLRps3jPOhuIq374a+KE8HMtkDEpM7sysLHP
# aQSbpYYf/F7X5jyC9sb6CMbMKE4t3JlSmMjawxtiVCpfSfABdIzcOHF9vixkJIMJ
# 1pqB/U9+2jJXbgQwseMYCTXao9ZI1Q8hd8vZpdgzgavdJVdraNKkQ3X488mNtENN
# QDx0tP32Do82rb1BL9zmD0kVJiu2x3DQWwxZOw+9LGrzDDtamskTagmC0tmVzcnx
# cLUSgkAsJ/bBx1jkrrxFbzVk+cuTtKtr7G8BqcZA5OGC+Tf325EBrF3sM23hNvLE
# rLw94X1RkGqRSCvDgc/+XAoQDj7pB/5v3YgZYErbIdWy3hddfz3JIyQ/pp//lJyn
# ZT1Kjv/EDtZNNGMvlOUqDEB/lN7F8Flduap+t/YUQO0GqheelG/8swqFmwKtruEw
# fcRL6ATe1Jntk27gawvu1vLAvLrfZFrZgX/65Yz6xTYO+wSpcBn2euuEkVnF/JgB
# +tRvcvt0TsCZBFaVcYk54No5/ZX2OsRyVLVPuYsy2sIoytmyRC4nwVi/aJrqQLPI
# 7P5dbEQH5daocGEuIPzJ5Pk9Cdpo5zFkMK8wd58c+RBY/tyA17Msnn0Vmx39echI
# MdxJJF9fFRzn/KxSKghRZsUNPWpYQquzNmA1d+LMKTs8/6GCDiwwgg4oBgorBgEE
# AYI3AwMBMYIOGDCCDhQGCSqGSIb3DQEHAqCCDgUwgg4BAgEDMQ0wCwYJYIZIAWUD
# BAIBMIH/BgsqhkiG9w0BCRABBKCB7wSB7DCB6QIBAQYLYIZIAYb4RQEHFwMwITAJ
# BgUrDgMCGgUABBSKdVltbmugAvSbBhzptH1XZseayAIVANyecCm8ELiHEEYWyOZ9
# kat7CQVeGA8yMDIzMDIxMzE0NTQxMlowAwIBHqCBhqSBgzCBgDELMAkGA1UEBhMC
# VVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1h
# bnRlYyBUcnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGlt
# ZVN0YW1waW5nIFNpZ25lciAtIEczoIIKizCCBTgwggQgoAMCAQICEHsFsdRJaFFE
# 98mJ0pwZnRIwDQYJKoZIhvcNAQELBQAwgb0xCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24gVHJ1c3QgTmV0d29y
# azE6MDgGA1UECxMxKGMpIDIwMDggVmVyaVNpZ24sIEluYy4gLSBGb3IgYXV0aG9y
# aXplZCB1c2Ugb25seTE4MDYGA1UEAxMvVmVyaVNpZ24gVW5pdmVyc2FsIFJvb3Qg
# Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTYwMTEyMDAwMDAwWhcNMzEwMTEx
# MjM1OTU5WjB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9y
# YXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxKDAmBgNVBAMT
# H1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwggEiMA0GCSqGSIb3DQEB
# AQUAA4IBDwAwggEKAoIBAQC7WZ1ZVU+djHJdGoGi61XzsAGtPHGsMo8Fa4aaJwAy
# l2pNyWQUSym7wtkpuS7sY7Phzz8LVpD4Yht+66YH4t5/Xm1AONSRBudBfHkcy8ut
# G7/YlZHz8O5s+K2WOS5/wSe4eDnFhKXt7a+Hjs6Nx23q0pi1Oh8eOZ3D9Jqo9ITh
# xNF8ccYGKbQ/5IMNJsN7CD5N+Qq3M0n/yjvU9bKbS+GImRr1wOkzFNbfx4Dbke7+
# vJJXcnf0zajM/gn1kze+lYhqxdz0sUvUzugJkV+1hHk1inisGTKPI8EyQRtZDqk+
# scz51ivvt9jk1R1tETqS9pPJnONI7rtTDtQ2l4Z4xaE3AgMBAAGjggF3MIIBczAO
# BgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADBmBgNVHSAEXzBdMFsG
# C2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5zeW1jYi5jb20v
# Y3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20vcnBhMC4GCCsG
# AQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDovL3Muc3ltY2QuY29tMDYGA1Ud
# HwQvMC0wK6ApoCeGJWh0dHA6Ly9zLnN5bWNiLmNvbS91bml2ZXJzYWwtcm9vdC5j
# cmwwEwYDVR0lBAwwCgYIKwYBBQUHAwgwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMT
# EFRpbWVTdGFtcC0yMDQ4LTMwHQYDVR0OBBYEFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MB8GA1UdIwQYMBaAFLZ3+mlIR59TEtXC6gcydgfRlwcZMA0GCSqGSIb3DQEBCwUA
# A4IBAQB16rAt1TQZXDJF/g7h1E+meMFv1+rd3E/zociBiPenjxXmQCmt5l30otlW
# ZIRxMCrdHmEXZiBWBpgZjV1x8viXvAn9HJFHyeLojQP7zJAv1gpsTjPs1rSTyEyQ
# Y0g5QCHE3dZuiZg8tZiX6KkGtwnJj1NXQZAv4R5NTtzKEHhsQm7wtsX4YVxS9U72
# a433Snq+8839A9fZ9gOoD+NT9wp17MZ1LqpmhQSZt/gGV+HGDvbor9rsmxgfqrnj
# OgC/zoqUywHbnsc4uw9Sq9HjlANgCk2g/idtFDL8P5dA4b+ZidvkORS92uTTw+or
# WrOVWFUEfcea7CMDjYUq0v+uqWGBMIIFSzCCBDOgAwIBAgIQe9Tlr7rMBz+hASME
# IkFNEjANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3lt
# YW50ZWMgQ29ycG9yYXRpb24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdv
# cmsxKDAmBgNVBAMTH1N5bWFudGVjIFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0EwHhcN
# MTcxMjIzMDAwMDAwWhcNMjkwMzIyMjM1OTU5WjCBgDELMAkGA1UEBhMCVVMxHTAb
# BgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRlYyBU
# cnVzdCBOZXR3b3JrMTEwLwYDVQQDEyhTeW1hbnRlYyBTSEEyNTYgVGltZVN0YW1w
# aW5nIFNpZ25lciAtIEczMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# rw6Kqvjcv2l7VBdxRwm9jTyB+HQVd2eQnP3eTgKeS3b25TY+ZdUkIG0w+d0dg+k/
# J0ozTm0WiuSNQI0iqr6nCxvSB7Y8tRokKPgbclE9yAmIJgg6+fpDI3VHcAyzX1uP
# CB1ySFdlTa8CPED39N0yOJM/5Sym81kjy4DeE035EMmqChhsVWFX0fECLMS1q/Js
# I9KfDQ8ZbK2FYmn9ToXBilIxq1vYyXRS41dsIr9Vf2/KBqs/SrcidmXs7DbylpWB
# Jiz9u5iqATjTryVAmwlT8ClXhVhe6oVIQSGH5d600yaye0BTWHmOUjEGTZQDRcTO
# PAPstwDyOiLFtG/l77CKmwIDAQABo4IBxzCCAcMwDAYDVR0TAQH/BAIwADBmBgNV
# HSAEXzBdMFsGC2CGSAGG+EUBBxcDMEwwIwYIKwYBBQUHAgEWF2h0dHBzOi8vZC5z
# eW1jYi5jb20vY3BzMCUGCCsGAQUFBwICMBkaF2h0dHBzOi8vZC5zeW1jYi5jb20v
# cnBhMEAGA1UdHwQ5MDcwNaAzoDGGL2h0dHA6Ly90cy1jcmwud3Muc3ltYW50ZWMu
# Y29tL3NoYTI1Ni10c3MtY2EuY3JsMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMA4G
# A1UdDwEB/wQEAwIHgDB3BggrBgEFBQcBAQRrMGkwKgYIKwYBBQUHMAGGHmh0dHA6
# Ly90cy1vY3NwLndzLnN5bWFudGVjLmNvbTA7BggrBgEFBQcwAoYvaHR0cDovL3Rz
# LWFpYS53cy5zeW1hbnRlYy5jb20vc2hhMjU2LXRzcy1jYS5jZXIwKAYDVR0RBCEw
# H6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0yMDQ4LTYwHQYDVR0OBBYEFKUTAamf
# hcwbbhYeXzsxqnk2AHsdMB8GA1UdIwQYMBaAFK9j1sqjToVy4Ke8QfMpojh/gHVi
# MA0GCSqGSIb3DQEBCwUAA4IBAQBGnq/wuKJfoplIz6gnSyHNsrmmcnBjL+NVKXs5
# Rk7nfmUGWIu8V4qSDQjYELo2JPoKe/s702K/SpQV5oLbilRt/yj+Z89xP+YzCdmi
# WRD0Hkr+Zcze1GvjUil1AEorpczLm+ipTfe0F1mSQcO3P4bm9sB/RDxGXBda46Q7
# 1Wkm1SF94YBnfmKst04uFZrlnCOvWxHqcalB+Q15OKmhDc+0sdo+mnrHIsV0zd9H
# CYbE/JElshuW6YUI6N3qdGBuYKVWeg3IRFjc5vlIFJ7lv94AvXexmBRyFCTfxxEs
# HwA/w0sUxmcczB4Go5BfXFSLPuMzW4IPxbeGAk5xn+lmRT92MYICWjCCAlYCAQEw
# gYswdzELMAkGA1UEBhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9u
# MR8wHQYDVQQLExZTeW1hbnRlYyBUcnVzdCBOZXR3b3JrMSgwJgYDVQQDEx9TeW1h
# bnRlYyBTSEEyNTYgVGltZVN0YW1waW5nIENBAhB71OWvuswHP6EBIwQiQU0SMAsG
# CWCGSAFlAwQCAaCBpDAaBgkqhkiG9w0BCQMxDQYLKoZIhvcNAQkQAQQwHAYJKoZI
# hvcNAQkFMQ8XDTIzMDIxMzE0NTQxMlowLwYJKoZIhvcNAQkEMSIEIB/Mfg2G4wKW
# Mvhtd44hX9fRh71ZfVG1eUcPQXkYt/QxMDcGCyqGSIb3DQEJEAIvMSgwJjAkMCIE
# IMR0znYAfQI5Tg2l5N58FMaA+eKCATz+9lPvXbcf32H4MAsGCSqGSIb3DQEBAQSC
# AQCCeWCxY5f4YLDnskx1xAUm4lC8EooPIAxxbD1P3P92bNcOkTApOPMQNMEagmzs
# VcVPJgJJkd+tndbFsCSX8AoLxRD4imme6YVKc0yxpIxs/3FVfXdYMlZ2dvqChR+e
# tkorhq9WyBhVrkT1Q6gmdbhO6cpzdSfHhfuyUhy8DZbNl5dmCTNqpFKUckX97Ifb
# AiaaVl/n9Th/XI7P7BRGsj05Ztzdj7OMfMN3zGlJEFHJb4C/JZAJ0G2nbFfVo4Sw
# OPdmoT0g4V7qiaLzE/Aq49nO9d1uRSrIr4cS9lYQe5XcM0XR1o6LJ+CcThcLEV4n
# SY9SZhga0veyfNexDqm47K6H
# SIG # End signature block
