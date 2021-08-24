<#
   =====================================================
   NB: BEFORE YOU FIRST RUN THIS SCRIPT ON A NEW PC
   =====================================================

  1. Change execution policy to allow execution of signed scripts on this machine
    This is a reasonable security posture; default setting is: "Restricted", means no scripts at all may run.
    PS> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force
 
    *What this does:*
    Machine ExecutionPolicy is stored at: HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy
    This command sets this value to: "RemoteSigned"

  2. Manually unblock this script (as it's not digitally signed)
    PS> Unblock-File -Path .\Setup-PC.ps1

    *What this does:*
    Windows retains a hidden "Zone Identifer" file for files downloaded from the Internet
    (Most of the time - it depends on which software was used to download it).
    You can read these hidden files using following command:
    PS> Get-Content -Path [filename] -Stream Zone.Identifier
    Not all files have this set, but you should definitely find some in your Downloads folder.
    Run this command to examine all files in your downloads folder
    PS> Get-ChildItem -Path $env:USERPROFILE\Downloads | ForEach-Object {Get-Content -Path $_.FullName -Stream Zone.Identifier -ErrorAction SilentlyContinue}
    You are likely to see something like this (amongst other stuff):
    [ZoneTransfer]
    ZoneId=3
    The meaning of the ZoneId may be found in the registry HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\<zoneId>\Description
    ZoneId 3 generally means Internet
    The "Unblock-File" command removes the Zone Identifier setting for the specified file, allowing downloaded files to be executed.
#>

<#
.SYNOPSIS
Script to install application software and adjust some OS settings
.windo
This script takes as it's input a JSON file of packages and installs them on the machine.
It should save a lot of time when setting up a new PC from scratch.
It can also be used to keep all installed software up-to-date
.PARAMETER PackageFile 
A text file [JSON] containing package details
.PARAMETER Upgrade
Attempt software upgrade rather than install
.PARAMETER OnlyRun
Only run packages from a specific provider, or just a specific package. Format: <provider>[:<package>]
.PARAMETER Force
Force execution, even if recent. (Some updates otherwise only performed weekly)
.EXAMPLE
Setup-PC.ps1 -PackageFile dw_packages.json -Upgrade
This will attempt to upgrade all the software described in dw_packages.json
[SkipInstall: False]
.LINK 
#>

# Need to run as administrator
#Requires -RunAsAdministrator

Param (
    [Parameter(Mandatory = $true, Position = 1)][string]$PackageFile="",
    [switch]$Upgrade=$false,
    [switch]$SkipInstall=$false,
    [string]$OnlyRun="",
    [switch]$Force=$false,
    [switch]$ShowInstalled=$false,
    [switch]$ShowChocolatey=$false)

#################################################
#
# Global variables
#
#################################################

## START CONSTANTS ##

[string]$global:install_folder = "c:\install"
[string]$global:bb_folder      = "c:\BB"
[string]$global:reg_home       = 'HKLM:\SOFTWARE\Dave'
[string]$global:app_name       = "Setup-PC"
[string]$global:windows_ver    = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

[hashtable]$global:custom_actions = @{
    vscode_extensions   = "Install-VsCodeExtensions"
    firefox_extensions  = "Install-FirefoxExtensions"
    boost_libraries     = "Install-BoostLibraries"
    git_setup           = "Setup-Git"
    windows_folders     = "Format-WindowsExplorer"
    update_ps_help      = "Update-PowershellHelp"
    windows_updates     = "Install-WindowsUpdates"
    psreadline          = "Install-PowershellModule"
    wsl2                = "Install-WSL2"
}

## END CONSTANTS ##

[string]$global:git_private_key = ""
[hashtable]$global:choco_packages = @{}
[array]$global:choco_forupgrade = @()
[hashtable]$global:all_products = @{}
[string]$global:bitbucket_workspace_id = ""
[switch]$global:nolog = $false

if ($ShowInstalled -or $ShowChocolatey) {
    $global:nolog = $true
}

#################################################
#
# Simple logging function
#
#################################################

function Applog {
    if ($global:nolog) {return}
    $message=$args[0]
    $timestamp=Get-Date -UFormat "%Y/%m/%d %H:%M:%S"
    Write-Host -ForegroundColor Cyan "$timestamp $message"
}

#################################################
#
# Validate inputs
#
#################################################

if ([string]::IsNullOrEmpty($PackageFile)) {
    Applog "Must specify package file with -PackageFile"
    exit 1
}

#################################################
# Enable TLS1.2
#################################################
function Enable-TLS12 {
    # Ensure TLS1.2 enabled
    #
    # You can see current enabled download protocols as follows:
    # PS> [System.Net.ServicePointManager]::SecurityProtocol
    # Usually defaults to: Ssl3, Tls

    # Use bitwise-or to update this value (-bor) to enable TLSv1.2
    # See all values listed here: https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-secpkgcontext_connectioninfo
    # TLSv1.2 setting = SP_PROT_TLS1_2_SERVER|SP_PROT_TLS1_2_CLIENT = 0x400|0x800 = 0xC00 = 3072
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
    # Inspecting [System.Net.ServicePointManager]::SecurityProtocol should now reveal: "Ssl3, Tls, Tls12"
}

#################################################
#
# We use Chocolatey to install most of our software
# See: https://chocolatey.org/
#
#################################################

function Install-Choco {
    Param ([switch]$Upgrade=$false)

    # Use 7zip compression for faster downloads
    $env:chocolateyUseWindowsCompression = $true

    Enable-TLS12

    # Is Chocolatey installed?
    $choco = Get-Command choco -ErrorAction SilentlyContinue
    if ($choco) {
        # Choco exe is shimmed, so can't rely on this version number
        # Some jiggery to get the actual version:
        $choco_version = (Get-Command ((choco --shimgen-noop)[1] -split ": ")[1]).FileVersionInfo.ProductVersion
        if ($Upgrade) {
            $latest_chocolatey = (choco list chocolatey --exact --limit-output).Split("|")[1]
            if ($latest_chocolatey -eq $choco_version) {
                Applog "Latest chocolatey already installed [v$choco_version]"
            } else {
                Applog "Chocolatey v$choco_version installed, v$latest_chocolatey available; upgrading chocolatey..."
                choco upgrade chocolatey
            }
        } else {
            Applog "Chocolatey already installed [v$choco_version]."
        }
    } else {
	    Applog "Chocolatey not installed; about to install."

        # Install Chocolatey using PowerShell script from Chocolatey site
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

        $choco = Get-Command choco -ErrorAction SilentlyContinue
        if ($choco) {
            Applog "Successfully installed choco"
        } else {
            Applog "Failed installing choco"
            exit # fatal
        }

        # Allow installation of chocolatey applications without confirmation
        choco -r feature enable -n allowGlobalConfirmation
    }
}

#################################################
#
# Install Nuget manually - to avoid prompt
#
#################################################

function Install-Nuget {
    Param ([switch]$Upgrade=$false)
    
    $nuget = Get-PackageProvider | Where-Object {$_.Name -eq "NuGet"}
    if (!$nuget) {
        Applog "Nuget not installed; installing..."
        Install-PackageProvider -Name NuGet -Force
        $nuget = Get-PackageProvider | Where-Object {$_.Name -eq "NuGet"}

        $Upgrade=$false

        if ($nuget) {
            $installed_state = "successfully"
        } else {
            Applog "Failed installing Nuget"
            exit 1
        }
    } else {
        $installed_state = "already"
    }

    $nuget_version = "{0}.{1}.{2}.{3}" -f $nuget.Version.Major, $nuget.Version.Minor, $nuget.Version.Build, $nuget.Version.Revision


    if ($Upgrade) {
        $new_nuget = Find-PackageProvider -Name "NuGet"
        $latest_nuget = $new_nuget.Version
    } else {
        $latest_nuget = $nuget_version
    }

    Applog "Nuget v$nuget_version $installed_state installed [latest=v$latest_nuget]"

    if ($Upgrade -and $nuget_version -ne $latest_nuget) {
        Applog "Installing latest NuGet..."
        Install-PackageProvider -Name NuGet -Force
    }
}

#################################################
# Install vscode extensions
#################################################
function Install-VsCodeExtensions {
    param([switch]$Force=$false)

    [array]$installed_extensions = code --list-extensions | ForEach-Object {$_.toLower()}
    [array]$extensions = @(
        "ms-vscode.powershell",
        "golang.go",
        "hashicorp.terraform",
        "ms-vscode.cpptools",
        "ms-python.python",
        "amazonwebservices.aws-toolkit-vscode",
        "ms-vscode-remote.remote-wsl"
    )

    foreach ($e in $extensions) {
        if (!$installed_extensions.Contains($e)) {
            code --install-extension $e
        }
    }
}

#################################################
# Install-FirefoxExtension
#################################################
function Install-FirefoxExtension
{
    param([string]$Name="")

    $webpage=Invoke-Webrequest "https://addons.mozilla.org/en-GB/firefox/addon/$Name/"
    if (!$webpage) {
        Applog "Failed to read Firefox addons page"
        return
    }

    $xpi = $webpage.ToString().Replace("\u002F","/") -split 'https://' -replace "xpi.*","xpi" | Where-Object {$_ -like "addons.mozilla.org/firefox/downloads/*xpi"}
    if (!$xpi)
    {
        Applog "Failed to find xpi download link"
        return
    }
    $url = "https://" + $xpi
    Download-FromInternet -Url $url

    # Locate firefox
    $ff="$env:ProgramFiles\Mozilla FireFox\firefox.exe"
    if (!(Test-Path -Path $ff)) {
        Applog "Failed to locate Firefox"
        return
    }

    $xpi = Get-Localfilename -Url $url
    if (!$xpi -or !(Test-Path -Path $xpi)) {
        Applog "Failed to locate addon file"
        return
    }

    # Command-line not working
    # TODO: Use AHK to drag-drop downloaded files to firefox
    # Applog "$ff -install-global-extension $xpi | more"
}

#################################################
# Install Firefox extensions
#################################################
function Install-FirefoxExtensions {
    param([switch]$Force=$false)

    # Locate firefox
    $ff="$env:ProgramFiles\Mozilla FireFox\firefox.exe"
    if (!(Test-Path -Path $ff)) {
        Applog "Failed to locate Firefox"
        return
    }

    [array]$extensions = @(
        "lastpass-password-manager",
        "ublock-origin",
        "privacy-badger17",
        "cisco-webex-extension"
    )

    [array]$installed_extensions = @()

    foreach ($e in $extensions) {
        if (!$installed_extensions.Contains($e)) {
            Install-FirefoxExtension -Name $e
        }
    }
}

#################################################
# Save TimeLastRun for specified item
#################################################
function Save-RunTime {
    param([string]$Item="")

    $property = "TimeLastRun"
    if ($Item) {
        $property += "_$Item"
    }

    [string]$reg_keyname = $global:reg_home + '\' + $global:app_name
    [string]$time_last_run = Get-Date -UFormat "%Y/%m/%d %H:%M:%S"
    Set-ItemProperty -Path $reg_keyname -Name $property -Value $time_last_run
}

#################################################
# Check if we've recently run this
#################################################
function Assert-TheSameEra {
    param(
        [string]$Era="",
        [string]$Item="")

    # Skip if already run this era; default era = today

    $property = "TimeLastRun"
    if ($Item) {
        $property += "_$Item"
    }

    [string]$reg_keyname = $global:reg_home + '\' + $global:app_name
    $time_last_run = (Get-ItemProperty -Path $reg_keyname -Name $property -ErrorAction SilentlyContinue).$property
    if (!$time_last_run) {
        return $false
    }

    [datetime]$dt = [datetime]::parse($time_last_run)
    if (!$dt) {
        return $false
    }

    [datetime]$now = Get-Date

    # Not this year => not the same!
    if ($now.Year -ne $dt.Year) {
        return $false
    }

    # Same month?
    if ($Era -eq "month") {
        return ($now.Month -eq $dt.Month)
    }

    # Same week?
    if ($Era -eq "week") {
        $w = Get-Date -UFormat "%V" -Date $dt
        $nw = Get-Date -UFormat "%V" -Date $now

        return ($w -eq $nw)
    }

    # Same day?
    return ($now.DayOfYear -eq $dt.DayOfYear)
}

#################################################
# Update Powershell help
#################################################
function Update-PowershellHelp {
    param([switch]$Force=$false)

    $name = "UpdatePsHelp"

    # Skip if already run this era
    $era = "week"
    if ($Force -eq $false -and (Assert-TheSameEra -Era $era -Item $name)) {
        Applog "Skipping updating Powershell help, as already run this $era."
        return
    }
     
    Applog "Updating Powershell help..."
    Update-Help -Force -ErrorAction SilentlyContinue

    Save-RunTime -Item $name
}

#################################################
# Install Powershell Module
#################################################
function Install-PowershellModule {
    param(
        [string]$ModuleName="",
        [string]$Repository="PSGallery",
        [switch]$Beta=$false
    )

    if ([string]::IsNullOrEmpty($ModuleName)) {
        Applog "Must specify a module name to install!"
        return
    }

    Applog "Fetching $ModuleName from [$Repository]..."

    # Check if already installed
    $module = Get-Module | Where-Object {$_.Name -eq $ModuleName}
    if ($null -eq $module) {

        # Prepare install_folder
        if (!(Test-Path -Path $global:install_folder)) {
            New-Item -ItemType directory -Path $global:install_folder -Force | Out-Null
        }

        # Check if module already downloaded
        [array]$module_folders = (Get-Module -ListAvailable).Path -replace "Modules.*", "Modules" | Get-Unique
        [array]$module_matches = $module_folders | ForEach-Object {$_ + "\$ModuleName"} | Test-Path -PathType Container | Select-String "True"
        
        if ($module_matches.Count -eq 0) {
            $moduleFolder = $env:ProgramFiles + "\WindowsPowerShell\Modules"
            Applog "Check if module available in $repository"
            $module=Find-Module -Name $ModuleName -Repository $Repository
            if ($module) {
                Applog "Downloading $ModuleName from $repository..."
                Save-Module -Name $ModuleName -Path $global:install_folder -Repository $Repository

                $sourcePath = $global:install_folder + "\" + $ModuleName
                Copy-Item -Path $sourcePath -Destination $moduleFolder -Recurse
            } else {
                Applog "Module: $ModuleName not available from $Repository."
                return
            }
        }
    } else {
        $ver = $module.Version.ToString()
        Applog "Module $ModuleName v$ver downloaded and available"
    }

    if ($Beta) {
        $installCommand = "Install-Module -Name $ModuleName -Force -AllowPrerelease"
    } else {
        $installCommand = "Install-Module -Name $ModuleName -Force"
    }

    Applog ">> $installCommand"
    Invoke-Expression $installCommand
}

#################################################
# Install Windows Updates
#################################################
function Install-WindowsUpdates {
    param([switch]$Force=$false)

    $name = "WindowsUpdates"

    # Skip if already run this era
    $era = "week"
    if ($Force -eq $false -and (Assert-TheSameEra -Era $era -Item $name)) {
        Applog "Skipping windows update, as already run this $era."
        return
    }

    Applog "Starting Windows Update..."

    Install-PowershellModule -ModuleName "PSWindowsUpdate"

    Applog "Downloading Windows Updates..."
    Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Download -IgnoreReboot

    Applog "Installing Windows Updates..."
    Get-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install 

    Applog "Windows Update finished"
    
    Save-RunTime -Item $name
}

#################################################
# Install Windows Subsystem for Linux 2
#################################################
function Install-WSL2 {
    $wsl_command = Get-Command -Name wsl -ErrorAction SilentlyContinue
    if ($wsl_command) {
        Applog "WSL already installed"
        return
    }

    dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
    dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
    wsl --set-default-version 2

    Applog "Opening WSL2 page in Windows Store. Please choose your preferred distribution."
    Applog "Press any key to continue..."
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown');

    Start-Process -FilePath "https://aka.ms/wslstore"
}

#################################################
# Receive-FromGithub
#################################################
function Receive-FromGithub {
    param(
        [string]$Project="",
        [string]$Package="")

    $url = "https://api.github.com/repos/$Project/$Package/releases/latest"
    $curl = $ProgramData + "\chocolatey\bin\curl.exe"
    $download_url = & $curl $url | jq -r '.assets[].browser_download_url'
    
    Download-FromInternet -Url $download_url
}

#################################################
# Set key file permissions
#################################################
function Set-KeyFilePermissions {
    param([string]$KeyFile="")

    if (!$KeyFile -or $KeyFile.length -eq 0) {
        Applog "No key file specified"
        return
    }

    if (!(Test-Path -Path $KeyFile -PathType Leaf)) {
        Applog "Specified key file [$KeyFile] does not exist"
        return
    }

    $icacls_command = Get-Command -Name icacls -ErrorAction SilentlyContinue
    if (!$icacls_command) {
        Applog "Failed to find icacls.exe - needed for file permission adjustment"
        return
    }

    $icacls_ver = $icacls_command.Version
    Applog "Using icacls v$icacls_ver to adjust key file permissions to ${env:USERNAME}:(F) only"

    # Remove Inheritance
    icacls.exe $KeyFile /q /c /t /Inheritance:d >$null

    # Set Ownership to Owner
    icacls.exe $KeyFile /q /c /t /Grant ${env:USERNAME}:F >$null

    # Remove All Users, except for Owner
    icacls.exe $KeyFile /q /c /t /Remove Administrator "Authenticated Users" BUILTIN\Administrators BUILTIN Everyone System Users >$null
}

#################################################
# Generate Git Keys
#################################################

function Generate-GitKey {

    $global:git_private_key = ""

    # We need openssl.exe
    $openSSL_command = Get-Command openssl.exe
    if (!$openSSL_command) {
        $openSSL = $env:ProgramFiles+"\OpenSSL-Win64\bin\openssl.exe"
        if (!(Test-Path -Path $openSSL -PathType Leaf)) {
            # Try alternate path
            $openSSL = "C:\OpenSSL-Win64\bin\openssl.exe"
            if (!(Test-Path -Path $openSSL -PathType Leaf)) {
                Applog "OpenSSL is missing, please install"
                return
            }
        }
    }
    else {
        $openSSL = $openSSL_command.Source
    }

    # Build folder and key filenames
    $underscore_name = $env:USERNAME -replace "\.","_"
    Applog "Generating keys for:" $underscore_name
    $folder = ".\keys\openssl_"+$underscore_name
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    
    $pemFile = $folder+"\"+$underscore_name+"_bb_pem_priv_key.txt"
    $pemPubFile = $folder+"\"+$underscore_name+"_bb_pem_pub_key.txt"
    $sshPubFile = $folder+"\"+$underscore_name+"_bb_ssh_pub_key.txt"
    
    #
    # Generate PEM private key
    #
    if (!(Test-Path -Path $pemFile -PathType Leaf)) {
        # Use OpenSSL to generate private key in PEM format
        & $openSSL genrsa -out $pemFile 2048 2>$null
        if (!(Test-Path -Path $pemFile -PathType Leaf)) {
            Applog "Failed to build PEM file: $pemFile"
            return
        }
        Applog "Generated PEM private key: $pemFile"
        Set-KeyFilePermissions -KeyFile $pemFile
    } else {
        Applog "PEM file [$pemFile] already exists, not regenerating."
    }
   
    #
    # Extract public key from PEM private key
    #
    if (!(Test-Path -Path $pemPubFile -PathType Leaf)) {
        # Extract public key from private key (still PEM format)
        & $openSSL rsa -in $pemFile -pubout -out $pemPubfile 2>$null
        if (!(Test-Path -Path $pemPubFile -PathType Leaf)) {
            Applog "Failed to build PEM public file: $pemPubfile"
            return
        }
        Applog "Generated PEM public key: $pemPubFile"
        Set-KeyFilePermissions -KeyFile $pemPubFile
    } else {
        Applog "PEM public key [$pemPubFile] already exists, not regenerating."
    }
    
    #
    # Build SSH public key from PEM public key
    #

    if (!(Test-Path -Path $sshPubFile -PathType Leaf)) {
        # 1. Extract modulus and exponent from public key
        $modulus = (& $openSSL rsa -pubin -in $pemPubFile -text -noout | ForEach-Object { $_ -replace ":","" -replace " ","" } | select-string -notmatch Public,Modulus,Exponent) -join ''
        $modLen = "{0,0:x}" -f ($modulus.Length/2)
        $modLen = $modLen.PadLeft(8, "0")
        $exponent=& $openSSL rsa -pubin -in $pemPubFile -text -noout | ForEach-Object { $_ -replace ":","" -replace " ","" } | Select-String Exponent | ForEach-Object { $_ -replace "Exponent.*\(0x","" -replace "\)",""  }
        if ($exponent.Length%2) {
            $exponent = "0"+$exponent
        }
        $expLen = "{0,0:x}" -f ($exponent.Length/2)
        $expLen = $expLen.PadLeft(8, "0")
    
        # 2. Algorithm indicator: ssh-rsa
        $algInd = "7373682d727361" # ssh-rsa
        $algIndLen = "{0,0:x}" -f ($algInd.Length/2)
        $algIndLen = $algIndLen.PadLeft(8, "0")
    
        # 3. Build SSH key format (RFC 4716)
        $sshKey = $algIndLen + $algInd + $expLen + $exponent + $modLen + $modulus
    
        # 4. Convert ASCII-hex to binary
        $sshKeyBytes = [byte[]]::new($sshKey.Length / 2)
        For($i=0; $i -lt $sshKey.Length; $i+=2){
            $sshKeyBytes[$i/2] = [convert]::ToByte($sshKey.Substring($i, 2), 16)
        }
        
        # 5. base64 encode
        $sshKeyBase64=[Convert]::ToBase64String($sshKeyBytes)

        # 6. Write to file
        "ssh-rsa "+$sshKeyBase64 > $sshPubFile
        if (!(Test-Path -Path $sshPubFile -PathType Leaf)) {
            Applog "Failed to build SSH Public file: $sshPubFile"
            return
        }
        Applog "Generated SSH public key file: $sshPubFile"
        Set-KeyFilePermissions -KeyFile $sshPubFile
    } else {
        Applog "SSH public key [$sshPubFile] already exists, not regenerating."
    }

    $global:git_private_key = $pemFile
}

#################################################
# Ensure we have the correct ssh-agent
# up and running
#################################################

function Fix-SshAgent {
    # We should prefer user-installed openssh
    $user_installed_ssh = $env:ProgramFiles + "\OpenSSH\bin\ssh-agent.exe"
    $os_installed_ssh = $env:SystemRoot + "\System32\OpenSSH\ssh-agent.exe"

    [string]$user_installed_ver=""
    [string]$os_installed_ver=""

    [string]$correct_ver=""
    
    if (Test-Path $user_installed_ssh) {
        $user_installed_ver=(Get-Item $user_installed_ssh).VersionInfo.ProductVersion
        if (!$user_installed_ver) {
            # Read version from "ssh -V"
            $user_installed_ver = & "$env:ProgramFiles\OpenSSH\bin\ssh.exe" -V 2>&1
        }
        Applog "User-installed SSH present, version=[$user_installed_ver]"
        $correct_ver = "user"
    }

    if (Test-Path $os_installed_ssh) {
        $os_installed_ver=(Get-Item $os_installed_ssh).VersionInfo.ProductVersion
        Applog "OS-installed SSH present, version=[$os_installed_ver]"

        if (!$user_installed_ver) {
            $correct_ver = "os"
        }
    }

    [string]$ssh_installed_type=""
    $service = Get-Service ssh-agent
    if ($service) {
        $servicePath = (Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name='ssh-agent'").PathName

        if ($servicePath -eq $user_installed_ssh) {
            $ssh_installed_type = "user"
        } elseif ($servicePath -eq $os_installed_ssh) {
            $ssh_installed_type = "OS"
        } else {
            $ssh_installed_type = "unknown"
        }

        Applog "ssh-agent installed by $ssh_installed_type [$servicePath]"
    }

    # Stop service if installed and not the one we want
    if ($ssh_installed_type -ne $correct_ver -and $service) {
        $serviceName = $service.Name
        if ($service.Status -eq "Running") {
            Applog "Stopping incorrect ssh-agent"
            Stop-Service -Name $serviceName
        }

        # Set to manual if automatic
        if ($service.StartType -eq "Automatic") {
            Applog "[ssh-agent] was Automatic, setting to Manual"
            Set-Service -Name ssh-agent -StartupType Manual
        }
    }

    # Start service if installed and is the one we want
    if ($ssh_installed_type -eq $correct_ver -and $service) {
        if ($service.StartType -eq "Disabled") {
            Applog "[ssh-agent] was Disabled, setting to Manual"
            Set-Service -Name ssh-agent -StartupType Manual
        }
        Start-Service -Name ssh-agent
    }

    # Start agent manually if not service
    if ($user_installed_ssh -and $user_installed_ver) {
        $running_ssh = Get-Process | Where-Object {$_.Name -eq "ssh-agent"}
        if ($running_ssh.length -gt 0) {
            $ssh_agent_path = $running_ssh[0].Path
            $ssh_agent_pid_os  = $running_ssh[0].Id
            Applog "ssh-agent already running, though unusable (as SSH_AGENT_PID unknown): os_pid=$ssh_agent_pid_os [$ssh_agent_path]"
            Applog "This ssh-agent will be stopped following next reboot"
        }

        $ssh_agent_startup = & $user_installed_ssh
        Applog "Started user ssh-agent: $ssh_agent_startup"

        $ssh_auth_sock = (($ssh_agent_startup -split "; " | Select-String "SSH_AUTH_SOCK=") -split "=")[1]
        $ssh_agent_pid = (($ssh_agent_startup -split "; " | Select-String "SSH_AGENT_PID=") -split "=")[1]

        if (!$ssh_auth_sock -or !$ssh_agent_pid) {
            Applog "Failed extracting SSH_AUTH_SOCK/SSH_AGENT_PID from ssh-agent output [$ssh_agent_startup]"
            return
        }

        $env:SSH_AUTH_SOCK=$ssh_auth_sock
        $env:SSH_AGENT_PID=$ssh_agent_pid
    }
}

#################################################
# Load Git Key
#################################################

function Load-GitKey {

    Fix-SshAgent

    # Ensure ssh-agent running
    if (!(Get-Process | Where-Object {$_.Name -eq "ssh-agent"})) {
        Applog "Required ssh-agent is not running!"
        return
    }

    # Also need ssh-add to add the key
    $user_sshadd = $env:ProgramFiles + "\OpenSSH\bin\ssh-add.exe"
    $os_sshadd = $env:SystemRoot + "\System32\OpenSSH\ssh-add.exe"

    [string]$sshadd=""
    if ((Test-Path -Path $user_sshadd -PathType Leaf)) {
        $sshadd = $user_sshadd
    } elseif ((Test-Path -Path $os_sshadd -PathType Leaf)) {
        $sshadd = $user_sshadd
    } else {
        $sshadd_command = Get-Command ssh-add.exe
        if ($sshadd_command) {
            $sshadd = $sshadd_command.Source
        } else {
            Applog "Failed to find ssh-add, please reinstall OpenSSH"
            return
        }
    }

    # Do we have the SSH key?
    if (!$global:git_private_key -or $global:git_private_key.length -eq 0) {
        Applog "SSH private key not set"
        return
    }
    if (!(Test-Path -Path $global:git_private_key -PathType Leaf)) {
        Applog "SSH private key does not exist [$global:git_private_key]"
        return
    }

    # Add the key using ssh-add
    & $sshadd $global:git_private_key
}

#################################################
# Configure git and set up git ssh key
#################################################
function Setup-Git {

    $git_config = $env:USERPROFILE + "\.gitconfig"
    if ((Test-Path -Path $git_config -PathType Leaf)) {
        $name=git.exe config --global --get user.name
        $email=git.exe config --global --get user.email
        Applog "Git config already exists: Name=[$name], Email=[$email]."
    } else {
        Applog "Setting up basic git configuration..."

        $email = $env:USERNAME + "@" + $global:email_domain
        $lower_name = $env:USERNAME -replace "\."," "

        $textinfo = (Get-Culture).TextInfo
        $name = $TextInfo.ToTitleCase($lower_name)

        git.exe config --global --add user.name $name
        git.exe config --global --add user.email $email
    }

    $git_keys = Get-ChildItem -Path "HKCU:\Software\OpenSSH\Agent\Keys\"
    $first_key = $git_keys[0]
    if ($first_key.Name) {
        $key_id = Split-Path $first_key.Name -Leaf
        Applog "Git key already created and loaded: [$key_id]"
    } else {
        Generate-GitKey
        Load-GitKey
    }
}

#################################################
# Get bitbucket workspace id
#################################################
function Get-BbWorkspaceId {
    if ($global:bitbucket_workspace_id) {
        # Already got it
        return
    }

    [string]$reg_keyname = $global:reg_home + '\' + $global:app_name
    $global:bitbucket_workspace_id = (Get-ItemProperty -Path $reg_keyname -Name BitbucketWorkspaceId -ErrorAction SilentlyContinue).BitbucketWorkspaceId
    if (!$global:bitbucket_workspace_id) {
        $global:bitbucket_workspace_id = Read-Host "    Please enter your Bitbucket Workspace ID. To find this out:
        1. Login to https://bitbucket.org
        2. Go to profile settings
        3. See `"Workspace ID`"
        
    Bitbucket Workspace ID"

        # Save it if we got something
        if ($global:bitbucket_workspace_id) {
            Set-ItemProperty -Path $reg_keyname -Name BitbucketWorkspaceId -Value $global:bitbucket_workspace_id
        }
    }

    if (!$global:bitbucket_workspace_id) {
        Applog "Failed to read Bitbucket workspace id!"
        return
    }

    Applog "Using Bitbucket Workspace ID: $global:bitbucket_workspace_id"
}

#################################################
# 
# Adjust Windows explorer view to sane settings
#
#################################################

function Format-WindowsExplorer {
    Param ([switch]$Force=$false)

    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'

    # Use value "ShowSuperHidden" to check if this function has ever been called
    $showsuperhidden = (Get-ItemProperty -Path $key ShowSuperHidden).ShowSuperHidden

    if ($showsuperhidden -eq 0 -or $Force) {
        #
        # Set folder options
        # 
        Applog "Setting up folder options..."

        
        Set-ItemProperty -Path $key Hidden          -Type DWORD -Value 1 -Force -ErrorAction 0
        Set-ItemProperty -Path $key HideFileExt     -Type DWORD -Value 0 -Force -ErrorAction 0
        Set-ItemProperty -Path $key ShowSuperHidden -Type DWORD -Value 1 -Force -ErrorAction 0

        # Make changes effective now
        Applog "Restarting explorer..."
        $explorer = Get-Process | Where-Object {$_.Name -eq "explorer"}
        if ($null -eq $explorer) {
            Stop-Process -processname explorer
        }

        # Set Locale to en-GB
        Set-WinSystemLocale -SystemLocale en-GB
    }
}

#################################################
# 
# Read installed choco packages to global map
#
#################################################

function Get-InstalledChocoPackages {

    $choco_list=choco list --local-only | Select-String -NotMatch ".* .* .*" | Where-Object {$_.LineNumber -gt 1} | Where-Object { $_.Line -match "^[a-z|0-9].* [0-9].*$"}
    if (!$choco_list) {
        Applog "Failed to read packages with: choco list --local-only!"
        return
    }

    [array]$installed_packages=($choco_list -replace '^(.*) (.*)$','"${1}": "${2}",')
    if ($installed_packages.length -eq 0) {
        Applog "Failed to build array of installed choco packages."
        return
    }
    
    $installed_packages[0] = "{`"choco`":{" + $installed_packages[0]
    $installed_packages[-1] = $installed_packages[-1].Replace(',','}}')
    $installed_json = $installed_packages | ConvertFrom-Json -ErrorAction SilentlyContinue
    if (!$installed_json) {
        # Try again! (For some unknown reason, last entry adjustment sometimes hasn't happened!)
        Applog "First attempt failed, installed_packages=$installed_packages"
        $installed_packages[0] = "{`"choco`":{" + $installed_packages[0]
        $installed_packages[-1] = $installed_packages[-1].Replace(',','}}')
        $installed_json = $installed_packages | ConvertFrom-Json -ErrorAction SilentlyContinue
    }

    if (!$installed_json) {
        Applog "ALERT: Failed to determine Choco installed packages - please try again!"
        exit
    }

    $choco_psc = $installed_json.choco

    # $choco_psc is a PSCustomObject - need to manually convert to hashtable
    $choco_psc.psobject.properties | ForEach-Object { $global:choco_packages[$_.Name] = $_.Value }
    $choco_count = $global:choco_packages.count
    Applog "$choco_count choco packages installed"
}

#################################################
# 
# Get latest version of each installed choco
# package
#
#################################################

function Get-LatestChocoVersions {

    Applog "Check which choco packages are not latest versions..."

    [array]$package_lists = @()
    [string]$package_list = ""
    $global:choco_packages.Keys | ForEach-Object {
        $package_list = $package_list + " " + $_
        if ($package_list.length -gt 100) {
            $package_lists += $package_list
            $package_list = ""
        }
    }

    foreach ($package_list in $package_lists) {
        $cmd = "choco upgrade $package_list --noop"
        $results = (Invoke-Expression $cmd | Where-Object { $_ -match "is available based on your source"})
        $results
        $global:choco_forupgrade += $results -replace "You have ([a-z|0-9].*) v.* installed.*",'$1'
    }

    Applog "For upgrade: $global:choco_forupgrade"
}

#################################################
# 
# Read all installed software to global map
#
#################################################

function Get-AllInstalledSoftware {
    $keys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Wow6432node\Microsoft\Windows\CurrentVersion\Uninstall')

    foreach ($key in $keys) {
        $app_keys = ((Get-ChildItem -Path $key | Select-Object Name).Name) -replace "HKEY_LOCAL_MACHINE", "HKLM:"

        foreach ($app_key in $app_keys) {
            $product_code = Split-Path $app_key -Leaf
            $product_details = Get-ItemProperty -Path $app_key | Select-Object DisplayName, DisplayVersion, Publisher | Where-Object {$_.DisplayName.length -gt 0}
            if ($product_details) {
                $global:all_products[$product_code] = $product_details
            }
        }
    }

    $total_count = $global:all_products.count
    Applog "$total_count total software packages installed"
}

#################################################
# 
# Read property from MSI file
# Taken from: https://www.scconfigmgr.com/2014/08/22/how-to-get-msi-file-information-with-powershell/
#
#################################################

function Read-PropertyFromMsi {
    param(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo]$Path,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("ProductCode", "ProductVersion", "ProductName", "Manufacturer", "ProductLanguage", "FullVersion")]
        [string]$Property
    )
    Process {
        try {
            # Read property from MSI database
            $WindowsInstaller = New-Object -ComObject WindowsInstaller.Installer
            $MSIDatabase = $WindowsInstaller.GetType().InvokeMember("OpenDatabase", "InvokeMethod", $null, $WindowsInstaller, @($Path.FullName, 0))
            $Query = "SELECT Value FROM Property WHERE Property = '$($Property)'"
            $View = $MSIDatabase.GetType().InvokeMember("OpenView", "InvokeMethod", $null, $MSIDatabase, ($Query))
            $View.GetType().InvokeMember("Execute", "InvokeMethod", $null, $View, $null)
            $Record = $View.GetType().InvokeMember("Fetch", "InvokeMethod", $null, $View, $null)
            $Value = $Record.GetType().InvokeMember("StringData", "GetProperty", $null, $Record, 1)

            # Commit database and close view
            $MSIDatabase.GetType().InvokeMember("Commit", "InvokeMethod", $null, $MSIDatabase, $null)
            $View.GetType().InvokeMember("Close", "InvokeMethod", $null, $View, $null)           
            $MSIDatabase = $null
            $View = $null

            # Return the value
            return $Value
        } 
        catch {
            Write-Warning -Message $_.Exception.Message ; break
        }
    }
    End {
        # Run garbage collection and release ComObject
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($WindowsInstaller) | Out-Null
        [System.GC]::Collect()
    }
}

#################################################
# Helper fn to format file size
#################################################

Function Format-FileSize() {
    Param ([int]$size)
    if ($size -gt 1TB) {[string]::Format("{0:0.00} TB", $size / 1TB)}
    elseIf ($size -gt 1GB) {[string]::Format("{0:0.00} GB", $size / 1GB)}
    elseIf ($size -gt 1MB) {[string]::Format("{0:0.00} MB", $size / 1MB)}
    elseIf ($size -gt 1KB) {[string]::Format("{0:0.00} kB", $size / 1KB)}
    elseIf ($size -gt 0) {[string]::Format("{0:0.00} B", $size)}
    else {""}
}

#################################################
# Helper fn to get local filename
#################################################
function Get-Localfilename() {
    param([string]$Url)

    $filename = Split-Path -Path $Url -Leaf
    if (!$filename) {
        Applog "Unable to extract filename from url [$Url]"
        return
    }

    $global:install_folder + "\" + $filename
}


#################################################
# 
# Download file from Internet if not already downloaded
#
#################################################

function Download-FromInternet {
    param([string]$Url)

    if ([string]::IsNullOrEmpty($Url)) {
        Applog "Null Url"
        return
    }

    # Prepare install_folder
    if (!(Test-Path -Path $global:install_folder)) {
        New-Item -ItemType directory -Path $global:install_folder -Force | Out-Null
    }
    
    $filename = Split-Path -Path $Url -Leaf
    if (!$filename) {
        Applog "Unable to extract filename from url [$Url]"
        return
    }

    $local_filename =  $global:install_folder + "\" + $filename

    if ((Test-Path "$local_filename")) {
        Applog "File [$filename] already exists, skipping download."
    } else {
        Applog "About to download [$filename] from $Url"
        $client = new-object System.Net.WebClient
        $client.DownloadFile($Url, $local_filename)

        if ((Test-Path "$local_filename")) {
            $size = Format-FileSize((Get-Item $local_filename).length)
            Applog "Successfully downloaded $filename [$size]"
        } else {
            Applog "Failed downloading [$local_filename]."
            return
        }
    }
}

#################################################
# 
# Install the boost libraries
#
#################################################

function Install-BoostLibraries {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # 1. Identify latest boost version
    $boost_downloads = "https://dl.bintray.com/boostorg/release/"
    $dl_page = Invoke-Webrequest $boost_downloads
    if (!$dl_page) {
        Applog "Failed to read download page [$boost_downloads]"
        return
    }
    $subdir=$dl_page.Links | Where-Object {$_.href -like '[0-9]`.[0-9][0-9]`.[0-9]/'} | Select-Object href -Last 1
    $version_dot=($subdir.href) -replace "/",""
    $version_underscore=$version_dot.Replace('.','_')

    Applog "Latest available boost version: $version_dot"

    # 2. Download the zip file
    $boost_download_url = $boost_downloads + $version_dot + "/source/boost_" + $version_underscore + ".zip"
    Download-FromInternet -Url $boost_download_url

    # 3. Unzip

    # Prepare boost_home
    $boostHome=$env:ProgramFiles+"\boost"
    if (!(Test-Path -Path $boostHome -PathType Container)) {
        New-Item -ItemType directory -Path $boostHome -Force | Out-Null
    }
    
    # Is this boost version already installed?
    $boostFolder=$boostHome + "\boost_" + $version_underscore
    if ((Test-Path -Path $boostFolder -PathType Container)) {
        Applog "Boost folder already present [$boostFolder], not extracting zip"
    } else {
        Applog "Boost folder [$boostFolder] missing"
        $zip_name =  $global:install_folder + "\boost_" + $version_underscore + ".zip"
        if (!(Test-Path "$zip_name")) {
            Applog "Zip file [$zip_name] missing."
            return
        }
    
        Applog "Extracting $zip_name to $boostHome..."

        $args="x -o`"$boostHome`" -r -y $zip_name"
        Applog "Running: 7z.exe $args"
        Start-Process 7z.exe -Wait -ArgumentList $args

        if (!(Test-Path -Path $boostFolder -PathType Container)) {
            Applog "Failed extracting boost zip. (Boost folder doesn't exist: $boostFolder)"
            return
        }
    }

    # Ok - we have boost folder, but has b2 been built yet?
    $b2 = $boostFolder + "\b2.exe"
    if ((Test-Path -Path $b2 -PathType Leaf)) {
        Applog "b2 already exists, skipping bootstrap."
    } else {
        Applog "b2 missing [$b2], running bootstrap."
        $args="/c `"cd %ProgramFiles%\boost\boost_$version_underscore && .\bootstrap.bat`""
        Applog "Running: cmd.exe $args"
        Applog "Note: you may have to ctrl-C at end of bootstrap-build"
        Start-Process cmd.exe -Wait -ArgumentList $args

        if ((Test-Path -Path $b2 -PathType Leaf)) {
            Applog "Successfully built b2.exe"
        } else {
            Applog "Failed building b2.exe [bootstrap.bat]."
            return
        }
    }

    # Ok - so we have b2, but have libraries been built?
    $stage = $boostFolder + "\stage"
    if ((Test-Path -Path $stage -PathType Container)) {
        Applog "Stage already exists, skipping boost build."
    } else {
        Applog "Boost libraries missing, running b2.exe."
        $current_folder = Get-Location
        Set-Location -Path $boostFolder
        .\b2.exe
        Set-Location -Path $current_folder

        if ((Test-Path -Path $stage -PathType Container)) {
            Applog "Successfully built boost libraries."
        } else {
            Applog "Failed building b2.exe [bootstrap.bat]."
            return
        }
    }

    Applog "Boost installation successful."
}

#################################################
# Log start of upgrade session
#################################################

function Write-Startup {
    #
    # Read run count & time when last run
    #
    [int]$run_count = 0
    [string]$time_last_run = "never"

    # Does reg key exist?
    [string]$reg_keyname = $global:reg_home + '\' + $global:app_name
    $reg_key = Get-Item -Path $reg_keyname -ErrorAction SilentlyContinue
    if ($reg_key) {
        $reg_property = Get-ItemProperty -Path $reg_keyname -Name RunCount -ErrorAction SilentlyContinue
        if ($reg_property) {
            $run_count = $reg_property.RunCount
            $time_last_run = (Get-ItemProperty -Path $reg_keyname -Name TimeLastRun -ErrorAction SilentlyContinue).TimeLastRun
            if (!$time_last_run) {
                New-ItemProperty -Path $reg_keyname -Name TimeLastRun -Value "never" | Out-Null
                [string]$time_last_run = "never"
            }
        } else {
            New-ItemProperty -Path $reg_keyname -Name RunCount -Value 0 | Out-Null
        }
    } else {
        New-Item -Path $reg_keyname -Force
        New-ItemProperty -Path $reg_keyname -Name RunCount -Value 0 | Out-Null
        New-ItemProperty -Path $reg_keyname -Name TimeLastRun -Value "never" | Out-Null
    }

    Applog "===================================================================================="
    Applog "Starting up ${global:app_name}. [run_count=$run_count, time_last_run=$time_last_run, Windows 10 v$global:windows_ver]"
}

#################################################
# Log end of upgrade session
#################################################

function Write-Finish {
    [string]$reg_keyname = $global:reg_home + '\' + $global:app_name
    [int]$run_count = (Get-ItemProperty -Path $reg_keyname -Name RunCount -ErrorAction SilentlyContinue).RunCount
    ++$run_count
    Set-ItemProperty -Path $reg_keyname -Name RunCount -Value $run_count

    Save-RunTime
        
    Applog "Finished ${global:app_name}. [run_count=$run_count]"
}

#################################################
#
# Install a chocolatey package
#
#################################################

function Install-ChocoPackage {
    Param (
        [hashtable]$PackageInfo,
        [switch]$Upgrade=$false)

    $id = $PackageInfo.id
    $name = $PackageInfo.name
    $url = $PackageInfo.url

    if ([string]::IsNullOrEmpty($id) -or [string]::IsNullOrEmpty($name) -or [string]::IsNullOrEmpty($url)) {
        Applog "Null package information, require {id, name, url}."
        return
    }

    $installed_version = $global:choco_packages[$id]

    if ($Upgrade -and !$installed_version) {
        Applog "[$id] not installed, upgrade not possible."
        return
    }
    
    if (!$Upgrade -and $installed_version) {
        Applog "[$id] already installed, version=[$installed_version]"
        return
    }

    if ($Upgrade -and !($global:choco_forupgrade -contains $id)) {
        Applog "[$id] already on latest version [$installed_version]"
        return
    }

    if ($Upgrade) {
        $action = "upgrade"
        $actionDesc = "Upgrading"
    } else {
        $action = "install"
        $actionDesc = "Installing"
    }

    Applog "$actionDesc $name [$id]; for more info, see $url"
    
    $args = $PackageInfo.args
    if ($args) {
        Applog ">> choco $action $id -y --package-parameters `"$args`""
        choco $action $id -y --package-parameters `"$args`"
    } else {
        Applog ">> choco $action $id -y"
        choco $action $id -y
    }

    if ($? -eq $false) {
        $actionDesc = $actionDesc.toLower()
        Applog "Failed $actionDesc $id, error=[$LASTEXITCODE], exiting."
        exit 1;
    }
}

#################################################
#
# Install an MSI package
#
#################################################

function Install-MSIPackage {
    Param (
        [hashtable]$PackageInfo,
        [switch]$Upgrade=$false)

    $id = $PackageInfo.id
    $name = $PackageInfo.name
    $url = $PackageInfo.url
    $download_url = $PackageInfo.download_url

    if ([string]::IsNullOrEmpty($id) -or [string]::IsNullOrEmpty($name) -or [string]::IsNullOrEmpty($url -or [string]::IsNullOrEmpty($download_url))) {
        Applog "Null package information, require {id, name, url, download_url}."
        return
    }

    # Download installation file
    $msi_filename = Split-Path -Path $download_url -Leaf
    if (!$msi_filename) {
        Applog "Failed extracting MSI filename from [$download_url]"
        return
    }

    if (!(Test-Path -Path $global:install_folder)) {
        New-Item -ItemType directory -Path $global:install_folder -Force | Out-Null
    }

    $local_msi_name =  $global:install_folder + "\" + $msi_filename
    if ((Test-Path "$local_msi_name")) {
        Applog "Install file [$msi_filename] already exists, skipping download."
    } else {
        Applog "About to download [$download_url]"
        $client = new-object System.Net.WebClient
        $client.DownloadFile($download_url, $local_msi_name)
    }
    if (!(Test-Path "$local_msi_name")) {
        Applog "Failed downloading [$msi_filename], exiting."
        return
    }

    # Has this MSI already been installed?
    [System.IO.FileInfo]$msi_file = [System.IO.FileInfo]$local_msi_name
    $productCode = Read-PropertyFromMsi -Path $msi_file -Property "ProductCode"
    
    if (!$productCode) {
        Applog "Failed to read product code from MSI [$local_msi_name]"
        return
    }

    $installed_product = $global:all_products[$productCode]
    if ($installed_product) {
        $display_name = $installed_product.DisplayName
        $version = $installed_product.DisplayVersion
        $publisher = $installed_product.Publisher

        Applog "$name [$id] already installed as [$display_name]; version=$version, publisher=[$publisher]"
        return
    }

    # Install the software
    if ($Upgrade) {
        $actionDesc = "Upgrading"
    } else {
        $actionDesc = "Installing"
    }

    Applog "$actionDesc $name [$id]; for more info, see $url"

    $install_logs = $global:install_folder + "\logs"
    if (!(Test-Path -Path $install_logs)) {
        New-Item -ItemType directory -Path $install_logs -Force | Out-Null
    }
    $inst_log = $install_logs + "\" + $productCode + ".log"

    $args="/quiet /log $inst_log /i $local_msi_name $extra"
    Applog "Running: msiexec.exe $args"
    Start-Process msiexec.exe -Wait -ArgumentList $args

    # Check for success
    Get-AllInstalledSoftware
    $installed_product = $global:all_products[$productCode]
    if ($installed_product) {
        $display_name = $installed_product.DisplayName
        $version = $installed_product.DisplayVersion
        $publisher = $installed_product.Publisher

        Applog "Successfully installed $name as [$display_name]; version=$version, publisher=[$publisher]"
    } else {
        Applog "Failed to install [$name]."
        return
    }
}

#################################################
#
# Install a custom package
#
#################################################

function Install-CustomPackage {
    Param (
        [hashtable]$PackageInfo,
        [switch]$Force=$false)

    $id = $PackageInfo.id
    $name = $PackageInfo.name
    $url = $PackageInfo.url
    $desc = $PackageInfo.description

    if ([string]::IsNullOrEmpty($id) -or [string]::IsNullOrEmpty($name) -or [string]::IsNullOrEmpty($url) -or [string]::IsNullOrEmpty($desc)) {
        Applog "Null package information, require {id, name, url, description}."
        return
    }

    Applog "Applying custom action $id [$name]; for more info, see $url"

    $custom_install = $global:custom_actions[$id]
    if ($custom_install) {
        Applog "Found custom action for [$id], applying"
        if ($custom_install -eq "Install-PowershellModule") {
            & $custom_install -Module $id -Beta
        } else {
            & $custom_install -Force:$Force
        }
    } else {
        Applog "Failed to find custom action for [$id], skipping"
    }
}

#################################################
#
# Install all packages in the packagefile
#
#################################################

function Install-AllPackages {
    Param (
        [string]$PackageFile="",
        [switch]$Upgrade=$false,
        [string]$OnlyRun="",
        [switch]$Force=$false)

    # $OnlyRun parameter instructs us to only run specific provider or specific provider / package
    [string]$only_this_provider=""
    [string]$only_this_package=""
    [string]$only_logging=""
    if ($OnlyRun) {
        $only_run_instructions = $OnlyRun.Split(":")
        if ($only_run_instructions -and $only_run_instructions.length -gt 0) {
            $only_this_provider = $only_run_instructions[0]
            if ($only_this_provider.length -gt 0) {
                $only_this_package = $only_run_instructions[1]
                if ($only_this_package.Length -gt 0) {
                    $only_logging = "only_package=$only_this_provider`:$only_this_package"
                } else {
                    $only_logging = "only_provider=$only_this_provider"
                }
            }
        }
    }

    Applog "Processing package file: [$PackageFile], upgrade=$Upgrade $only_logging"

    if (!(Test-Path "$PackageFile")) {
        Applog "Package File [$PackageFile] does not exist."
        return
    }

    $packagefile_json = Get-Content -Path $PackageFile | ConvertFrom-Json
    if (!$packagefile_json) {
        Applog "Failed reading in JSON package file [$PackageFile]"
        return
    }

    $package_providers = $packagefile_json.package_providers
    if (!$package_providers -or $package_providers.length -eq 0) {
        Applog "Package file [$PackageFile] does not contain any package providers"
        return
    }

    [int]$active_providers=0
    foreach ($provider in $package_providers) {
        if ($provider.install_packages -eq "true") {
            ++$active_providers
        }
    }

    if ($active_providers -eq 0) {
        $package_providers_length = $package_providers.length
        Applog "No active providers found in package file, $package_providers_length providers found."
        return
    }

    Applog "About to process $active_providers active providers from package file [$PackageFile]..."

    [int]$provider_index=0
    [int]$attempted_packages=0
    foreach ($provider in $package_providers) {
        ++$provider_index
        $provider_name = $provider.name
        $provider_comment = $provider.comment
        $provider_install = $provider.install_packages

        [string]$skip_reason=""
        if ($provider_install -ne "true") {
            $skip_reason = "install_packages is not [true] it is [$provider_install]"
        }
        if (!$provider_name -or $provider.name.length -eq 0) {
            $skip_reason = "provider has no name"
        }
        if (!$provider.comment -or $provider.comment.length -eq 0) {
            $skip_reason = "provider has no comment"
        }
        if ($only_this_provider -and $provider_name -ne $only_this_provider) {
            $skip_reason = "restricted to [$only_this_provider]"
        }
        if ($provider.packages.length -eq 0) {
            $skip_reason = "no packages to install"
        }

        # Is provider supported?
        switch ($provider_name) {
            "chocolatey" {break}
            "msi"        {break}
            "custom"     {break}
            default      {$skip_reason = "provider unsupported"; break}
        } # endswitch

        if ($skip_reason) {
            Applog "Skipping provider #$provider_index [$provider_name] as $skip_reason."
            continue
        }

        Applog "-----------------------------------------------------------"
        Applog "Applying packages from provider #$provider_index [$provider_name]"
        Applog "Note: $provider_comment"

        # Install each package in turn
        [int]$package_index=0
        foreach ($package in $provider.packages) {
            ++$package_index
            $skip_reason=""
            # Required properties for each package: id, name, url
            # Other properties are optional / provider-specific
            $package_id = $package.id
            if (!$package.id -or $package.id.length -eq 0) {
                $skip_reason = "package has no id"
            }
            if (!$package.name -or $package.name.length -eq 0) {
                $skip_reason = "package has no name"
            }
            if (!$package.url -or $package.url.length -eq 0) {
                $skip_reason = "package has no url"
            }
            if ($only_this_package -and $package_id -ne $only_this_package) {
                $skip_reason = "restricted to [$only_this_package]"
            }
            $winver = $package.windows10_version
            if ($winver -and $global:windows_ver -lt $winver) {
                $skip_reason = "[$id] requires Windows 10 v$winver, [current version=$global:windows_ver]"
            }
            $skip = $package.skip
            if ($skip -and $skip -eq "true") {
                $skip_reason = "[$id] configured with skip=[true]"
            }

            if ($skip_reason) {
                Applog "Skipping package #$package_index [$package_id] as $skip_reason."
                continue
            }

            # Read the package information from this provider to a map - currently a PSObject
            [hashtable]$package_info = @{}
            $package.PSObject.Properties | ForEach-Object { $package_info[$_.Name] = $_.Value }
            
            Applog "Applying package `#$package_index [$package_id]..."

            switch ($provider.name) {
                "chocolatey" { Install-ChocoPackage  -PackageInfo $package_info -Upgrade:$Upgrade; break}
                "msi"        { Install-MsiPackage    -PackageInfo $package_info -Upgrade:$Upgrade; break}
                "custom"     { Install-CustomPackage -PackageInfo $package_info -Force:$Force; break}
                default      { Applog "ALERT: Should not be here #$package_index, $provider_name"; break}
            } # endswitch
            ++$attempted_packages
        } # endfor
        Applog "Finished applying packages for provider [$provider_name]"
    } # endfor

    Applog "Finished everything. Attempted $attempted_packages packages across $active_providers providers."
}

#################################################
# 
# MAIN
#
#################################################

# Must be 64-bit
if (![Environment]::Is64BitProcess) {
    Applog "Must run script in 64-bit Powershell"
    return
}

# Adjust execution policy for this process so all PowerShell scripts are executed
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

Write-Startup

# Pre-requisites
Install-Choco -Upgrade:$Upgrade
Install-Nuget

# Check what's already on this machine
Applog "Checking already installed software..."
Get-InstalledChocoPackages
Get-AllInstalledSoftware

if ($ShowInstalled) {
    $global:all_products.Values
    return
}

if ($ShowChocolatey) {
    $global:choco_packages
    return
}

if ($Upgrade) {
    Get-LatestChocoVersions
}

# Off we go!
Install-AllPackages -PackageFile $PackageFile -Upgrade:$Upgrade -OnlyRun $OnlyRun -Force:$Force

Write-Finish

return
