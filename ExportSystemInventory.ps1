<#
    .SYNOPSIS
    Exports System inventory

    .DESCRIPTION
    PowerShell script that exports System inventory such as hardware, missing drivers GPO, updates, etc

    .NOTES
        FileName:    ExportSystemInventory.ps1
        Author:      Richard tracy
        Contact:     richard.j.tracy@gmail.com
        Updated:     02-17-2022

        Version history:
        2.0.0 - Feb 17, 2022 - Added Category parameter
        1.0.0 - Sept 18, 2020 - Script created

    .PARAMETER ExportPath
    Defaults to user desktop under SystemExport folder

    .PARAMETER Category
    Default to All. Select a category group or individual category to export.
    Categories groups are:
        All --> Exports All areas
        Basic --> Exports Administrator, SYSTEMINFO, COMPUTERINFO
        AllSoftware --> Exports Software, Apps, FOD
        Hardware --> Exports Driver,Bitlocker, COMPUTERINFO, SYSTEMINFO, MSINFO
        OS --> Exports Services, Capabilties, Features, Defender, Updates
        Updates --> Exports Hotfixes, Updates
        GPO --> Exports Firewall, Applocker, GPO

    .EXAMPLE
    .\ExportSystemInventory.ps1

    .EXAMPLE
    .\ExportSystemInventory.ps1 -ExportPath c:\Temp\Exports

    .EXAMPLE
    .\ExportSystemInventory.ps1 -Category GPO
#>


Param(
    #change this to writable path (omit last slash, eg. C:\temp)
    $ExportPath = "$env:USERPROFILE\Desktop\SystemExport",

    [ValidateSet('All','Basic','AllSoftware','Hardware','OS','Updates','GPO','MSINFO','SYSTEMINFO','COMPUTERINFO','Bitlocker','Firewall','Applocker','Administrators','Drivers','Software','Services','Features','Capabilities','Defender','Hotfixes','Apps','FOD')]
    $Category = 'All'
)

##=====================
##  FUNCTIONS
##=====================

Function Get-LHSReliabilityRecords{
    [CmdletBinding()]

    param (
     [parameter(ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
      [string]$ComputerName = $Env:COMPUTERNAME,


      [ValidateSet("System", "Application")]
      [string]$LogName,


      [ValidateSet(
        "Microsoft-Windows-WindowsUpdateClient ",
         "Microsoft-Windows-WER-SystemErrorReporting",
         "Application Error",
         #"MsiInstaller",
         "Microsoft-Windows-UserPnp",
         "Microsoft-Windows-Setup",
         "Application Hang",
         "Application-Addon-Event-Provider",
         "EventLog")]
      [string]$SourceName
    )

    BEGIN{
        Set-StrictMode -Version Latest

        ${CmdletName} = $Pscmdlet.MyInvocation.MyCommand.Name
        Write-Verbose -Message "${CmdletName}: Starting Begin Block"
        Write-Debug -Message "${CmdletName}: Starting Begin Block"

        $params = @{Class = 'Win32_ReliabilityRecords'}
        $filter = $null
        if ($LogName) {$filter += "LogFile = '$LogName'"}
        if ($SourceName) {$filter += "AND SourceName ='$SourceName'"}
        if ($filter){
           if ($filter.StartsWith("AND ")){$filter = $filter.Remove(0, 4)}
           Write-Debug "`$filter : $filter"
           $params.Filter = $filter
        }


    }# end BEGIN

    PROCESS {

        $params.ComputerName = $ComputerName

        IF (Test-Connection -ComputerName $ComputerName -count 2 -quiet) {

            Get-WmiObject @params |
            Select-Object ComputerName, EventIdentifier, InsertionStrings, Logfile, Message,
               ProductName, RecordNumber, SourceName,
               @{N="TimeGenerated"; E={$_.ConvertToDatetime($_.TimeGenerated)}},
               User

        } Else {
            Write-Host "\\$ComputerName DO NOT reply to ping" -ForegroundColor red
        } # end IF (Test-Connection -ComputerName $Computer -count 2 -quiet)


    } # end PROCESS

    END {Write-Verbose "Function Get-LHSReliabilityRecords finished."}

} # function Get-LHSReliabilityRecords

Function Translate-ErrorCode ($ProblemDevices)
{
    ForEach($ProblemDevice in $ProblemDevices){
        $ErrorDesc = Switch ($ProblemDevice.ConfigManagerErrorCode){
            1 {"Device is not configured correctly."}
            2 {"Windows cannot load the driver for this device."}
            3 {"Driver for this device might be corrupted, or the system may be low on memory or other resources."}
            4 {"Device is not working properly. One of its drivers or the registry might be corrupted."}
            5 {"Driver for the device requires a resource that Windows cannot manage."}
            6 {"Boot configuration for the device conflicts with other devices."}
            7 {"Cannot filter."}
            8 {"Driver loader for the device is missing."}
            9 {"Device is not working properly. The controlling firmware is incorrectly reporting the resources for the device."}
            10 {"Device cannot start."}
            11 {"Device failed."}
            12 {"Device cannot find enough free resources to use."}
            13 {"Windows cannot verify the device's resources."}
            14 {"Device cannot work properly until the computer is restarted."}
            15 {"Device is not working properly due to a possible re-enumeration problem."}
            16 {"Windows cannot identify all of the resources that the device uses."}
            17 {"Device is requesting an unknown resource type."}
            18 {"Device drivers must be reinstalled."}
            19 {"Failure using the VxD loader."}
            20 {"Registry might be corrupted."}
            21 {"System failure. If changing the device driver is ineffective, see the hardware documentation. Windows is removing the device."}
            22 {"Device is disabled."}
            23 {"System failure. If changing the device driver is ineffective, see the hardware documentation."}
            24 {"Device is not present, not working properly, or does not have all of its drivers installed."}
            25 {"Windows is still setting up the device."}
            26 {"Windows is still setting up the device."}
            27 {"Device does not have valid log configuration."}
            28 {"Device drivers are not installed."}
            29 {"Device is disabled. The device firmware did not provide the required resources."}
            30 {"Device is using an IRQ resource that another device is using."}
            31 {"Device is not working properly.  Windows cannot load the required device drivers."}
        }
        Write-Host "$($ProblemDevice.Name) ($($ProblemDevice.DeviceID)): "
        Write-Host "`t$ErrorDesc"
    }
}

##=====================
##  MAIN
##=====================

#create export folder
#====================================================================
New-item $ExportPath -ItemType Directory -Force -ErrorAction SilentlyContinue | Out-Null

#grab system details
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'MSINFO') -or ($Category -eq 'Hardware') )
{
    Write-Host "Exporting MSINFO..." -NoNewline
    Start-Process 'msinfo32' -ArgumentList  "/report $ExportPath\msinfo.txt" -Wait -WindowStyle Hidden | Out-Null
    Write-Host "Done" -ForegroundColor Green
}
#grab Bitlocker details
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Bitlocker') -or ($Category -eq 'Hardware') )
{
    Write-Host "Exporting Bitlocker Information..." -NoNewline
    Get-BitLockerVolume -OutVariable Keyprotector | Select MountPoint,EncryptionMethod, `
                        AutoUnlockKeyStored,MetadataVersion,VolumeStatus,VolumeType,ProtectionStatus,LockStatus,`
                        EncryptionPercentage,@{Name = 'KeyProtector'; Expression = {($Keyprotector | Select -ExpandProperty Keyprotector).KeyprotectorType -join "|"} } `
                            | Export-Csv "$ExportPath\bitlockerinfo.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}
#grab Firewall Profile details
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Firewall') -or ($Category -eq 'GPO') )
{
    Write-Host "Exporting Firewall Information..." -NoNewline
    Get-NetFirewallProfile | select name, enabled | Export-Csv "$ExportPath\FirewallProfile.csv" -NoTypeInformation
    Get-NetFirewallRule | Select DisplayName,Description,DisplayGroup,Action,Direction,Enabled | Export-Csv "$ExportPath\FirewallRules.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grab Applocker Effective Policy
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Applocker') -or ($Category -eq 'GPO') )
{
    Write-Host "Exporting Applocker Effective Policy..." -NoNewline
    Get-AppLockerPolicy -Effective -Xml | Set-Content ("$ExportPath\AppliedAppLockerPolicies.xml")
    Write-Host "Done" -ForegroundColor Green
}
#grab Local Administrators details
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Administrator') -or ($Category -eq 'Basic') )
{
    Write-Host "Exporting Local Administrators..." -NoNewline
    Try{
        $Admins = Get-LocalGroupMember -Name "Administrators" -ErrorAction Stop
        $Admins | Export-Csv "$ExportPath\LocalAdministrators.csv" -NoTypeInformation
    }Catch{
        Start-Process 'cmd' -ArgumentList "/c net localgroup administrators > $ExportPath\LocalAdministrators.txt" -Wait -WindowStyle Hidden | Out-Null
        Start-Process 'cmd' -ArgumentList "/c net localgroup 'power users' > $ExportPath\PowerUsers.txt" -Wait -WindowStyle Hidden | Out-Null
    }
    Finally{
        Write-Host "Done" -ForegroundColor Green
    }
}
#grab Missing Driver information
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Drivers') -or ($Category -eq 'Hardware') )
{
    Write-Host "Exporting Missing Driver information..." -NoNewline
    $missingDrivers = Get-WmiObject Win32_PNPEntity | Where-Object{$_.ConfigManagerErrorCode -ne 0} | Select Name, DeviceID, ConfigManagerErrorCode
    $VGABasic = Get-WmiObject Win32_PNPEntity | Where-Object{$_.Name -Match "VGA"} | Select Name, DeviceID
    If($missingDrivers -or $VGABasic){
        $VGABasic | Export-CSV "$ExportPath\MissingDrivers.csv"
        $missingDrivers | Export-CSV "$ExportPath\MissingDrivers.csv" -Append

        Write-Host "missing drivers found" -ForegroundColor Yellow
        Translate-ErrorCode $missingDrivers
    }Else{
        Write-Host "No missing drivers" -ForegroundColor Green
    }

}

#grab system information
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'SYSTEMINFO') -or ($Category -eq 'Basic') -or ($Category -eq 'Hardware') )
{
    Write-Host "Exporting SYSTEMINFO..." -NoNewline
    Start-Process 'systeminfo' -ArgumentList  "> $ExportPath\systeminfo.txt" -Wait -WindowStyle Hidden | Out-Null
    Write-Host "Done" -ForegroundColor Green
}
#grab system information with Powershell
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'COMPUTERINFO') -or ($Category -eq 'Basic') -or ($Category -eq 'Hardware') )
{
    Write-Host "Exporting COMPUTERINFO..." -NoNewline
    Get-ComputerInfo | Select * | Export-Csv "$ExportPath\systeminfo.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grab all installed applications
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Software') -or ($Category -eq 'AllSoftware') )
{
    Write-Host "Exporting software list..." -NoNewline
    $x64bitApplications = Get-ChildItem HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall | % {Get-ItemProperty $_.PsPath} |
                                Where {$_.Displayname -and ($_.Displayname -match ".*")} | sort Displayname |
                                select DisplayName,Publisher,DisplayVersion,@{name="Architecture"; expression={"x64"}},InstallDate,InstallSource,UninstallString

    $x86bitApplications = Get-ChildItem HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall | % {Get-ItemProperty $_.PsPath} |
                                Where {$_.Displayname -and ($_.Displayname -match ".*")} | sort Displayname |
                                select DisplayName,Publisher,DisplayVersion,@{name="Architecture"; expression={"x86"}},InstallDate,InstallSource,UninstallString
    #combine list
    ($x64bitApplications + $x86bitApplications) | Get-Unique -AsString | Export-Csv "$ExportPath\InstalledApplications.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grab all services state
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Services') -or ($Category -eq 'OS') )
{
    Write-Host "Exporting services info..." -NoNewline
    Get-Service -Name * | Select Name,status | Export-Csv "$ExportPath\services.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grab all Install features
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Features') -or ($Category -eq 'OS') )
{
    Write-Host "Exporting list of installed features..." -NoNewline
    Get-WindowsOptionalFeature -Online | Select FeatureName,State | Export-Csv "$ExportPath\features.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grab all capabilities
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Capabilities') -or ($Category -eq 'OS') )
{
    Write-Host "Exporting list of installed Windows capabilities..." -NoNewline
    Get-WindowsCapability -Online | Select Name,State | Export-Csv "$ExportPath\capability.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grab defender definition versions
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Defender') -or ($Category -eq 'OS') )
{
    Write-Host "Exporting Windows Defender definition versions..." -NoNewline
    Get-MpComputerStatus | Select AMEngineVersion,AMServiceVersion,AMProductVersion,AntispywareSignatureVersion,AntivirusSignatureVersion,NISEngineVersion,NISSignatureVersion | Export-Csv "$ExportPath\DefenderDefinitions.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#get only hotfixes
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Hotfixes') -or ($Category -eq 'OS') -or ($Category -eq 'Updates') )
{
    Write-Host "Exporting list of installed hotfixes..." -NoNewline
    Get-HotFix | Select HotfixID,Description,InstalledOn | Sort Description | Export-Csv -Path "$ExportPath\hotfixes.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grabs all Apps installed for user
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Apps') -or ($Category -eq 'AllSoftware') )
{
    Write-Host "Exporting list of installed modern apps for users..." -NoNewline
    Get-AppxPackage -AllUsers | select Name,PublisherID,Architecture,Version,Status | Export-Csv -Path "$ExportPath\appxpackages-users.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#grabs all Apps installed for system
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Apps') -or ($Category -eq 'AllSoftware') )
{
    Write-Host "Exporting list of available modern apps for system..." -NoNewline
    Get-AppxProvisionedPackage -Online | select DisplayName,PublisherID,Version,@{name="Architecture"; expression={switch($_.Architecture){9 {"x64"}; 11 {"Nuetral"}}}} | Export-Csv -Path "$ExportPath\appxpackages-system.csv" -NoTypeInformation
    Write-Host "Done" -ForegroundColor Green
}

#gets information about all packages in a Windows image using Powershell module
#display installed “OnDemand Packages”, “Language Packages” or “Foundation Packages”
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'FOD') -or ($Category -eq 'AllSoftware') )
{
    Write-Host "Exporting list of installed FOD packages..." -NoNewline
    Try{
        Get-WindowsPackage -Online -ErrorAction Stop | Select PackageName,State,InstallTime,ReleaseType | Export-Csv "$ExportPath\FODpackages.csv" -NoTypeInformation
    }
    Catch{
        #gets information about all packages in a Windows image using DISM
        #====================================================================
        Write-Host "using old method..." -NoNewline -ForegroundColor Yellow
        dism /online /Get-Packages /Format:Table | Out-File "$ExportPath\PackagesByDISM.txt"
    }
    Finally{
        Write-Host "Done" -ForegroundColor Green
    }
}

#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Updates') -or ($Category -eq 'OS') )
{
    Write-Host "Exporting list of Windows update history..." -NoNewline
    Try{
        #$Session = New-Object -ComObject Microsoft.Update.Session; $Searcher = $Session.CreateUpdateSearcher(); $Searcher.Search("IsInstalled=1").Updates | Select Title,Description,IsInstalled,IsHidden,LastDeploymentChangeTime | Export-Csv -Path "$ExportPath\FODpackages.csv" -NoTypeInformation
        ## Check for update using ComObject method (to catch Office updates)
        [__comobject]$UpdateSession = New-Object -ComObject "Microsoft.Update.Session"
        [__comobject]$UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
        #  Indicates whether the search results include updates that are superseded by other updates in the search results
        $UpdateSearcher.IncludePotentiallySupersededUpdates = $false
        #  Indicates whether the UpdateSearcher goes online to search for updates.
        $UpdateSearcher.Online = $false
        [int32]$UpdateHistoryCount = $UpdateSearcher.GetTotalHistoryCount()
        If ($UpdateHistoryCount -gt 0) {
            [psobject]$UpdateHistory = $UpdateSearcher.QueryHistory(0, $UpdateHistoryCount) |
                    Select-Object -Property 'Title','Date',
                                            @{Name = 'Operation'; Expression = { Switch ($_.Operation) { 1 {'Installation'}; 2 {'Uninstallation'}; 3 {'Other'} } } },
                                            @{Name = 'Status'; Expression = { Switch ($_.ResultCode) { 0 {'Not Started'}; 1 {'In Progress'}; 2 {'Successful'}; 3 {'Incomplete'}; 4 {'Failed'}; 5 {'Aborted'} } } },
                                            @{name="Category"; expression={$_.ClientApplicationID}},
                                            'Description' |
                    Sort-Object -Property 'Date' -Descending

            ForEach ($Update in $UpdateHistory) {
                If ($Update.Operation -ne 'Other') {
                    $UpdateHistory += $Update
                }
            }

            $UpdateHistory | Export-Csv -Path "$ExportPath\FODpackages.csv" -NoTypeInformation


            $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($UpdateSession)
            $null = [Runtime.Interopservices.Marshal]::ReleaseComObject($UpdateSearcher)
        }
        Else {
            $message = 'Unable to detect Windows update history via COM object.'
            Write-host $message -ForegroundColor red -NoNewline
            $message | Out-File $ExportPath\errors.txt -Append
        }
    }
    Catch{
        $_.Exception.ErrorMessage | Out-File $ExportPath\errors.txt -Append
    }
    Finally{
        Write-Host "Done" -ForegroundColor Green
    }
}

#exports Group Policy RSOP (must have GroupPolicy Module installed)
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'GPO') )
{
    Write-Host "Exporting group policies..." -NoNewline
    Try{
        Get-GPResultantSetOfPolicy -ReportType Xml -Path "$ExportPath\GPResultantSetOfPolicy.xml" | Out-null
        Get-GPResultantSetOfPolicy -ReportType Html -Path "$ExportPath\GPResultantSetOfPolicy.html" | Out-null

        #Get-GPResultantSetOfPolicy -user ($env:Domain + '\' + $env:USERNAME) -Computer $env:COMPUTERNAME -ReportType Html -Path "$ExportPath\GPResultantSetOfPolicy.html"
        [xml]$gpoxml = Get-Content "$ExportPath\GPResultantSetOfPolicy.xml"

        $gpoxml.DocumentElement.UserResults.GPO | select name, @{LABEL="LinkOrder";EXPRESSION={$_.link.linkorder}},@{LABEL="Type";EXPRESSION={'UserPolicy'}} | Export-Csv "$ExportPath\UserGroupPolicies.csv" -NoTypeInformation
        $gpoxml.DocumentElement.ComputerResults.GPO | select name, @{LABEL="LinkOrder";EXPRESSION={$_.link.linkorder}},@{LABEL="Type";EXPRESSION={'ComputerPolicy'}} | Export-Csv "$ExportPath\ComputerGroupPolicies.csv" -NoTypeInformation

        #export rsop
        $rsop = $gpoxml.DocumentElement.ComputerResults.GPO + $gpoxml.DocumentElement.UserResults.GPO

    }
    Catch{
        $_.Exception.ErrorMessage | Out-File $ExportPath\errors.txt -Append
    }
    Finally{
        #simple method of exporting gpresult
        Start-Process 'gpresult' -ArgumentList  "> $ExportPath\gpresult.txt" -Wait -WindowStyle Hidden | Out-Null
        Write-Host "Done" -ForegroundColor Green
    }
}

#exports Performance Data using Reliability Monitor
#====================================================================
If( ($Category -eq 'All') -or ($Category -eq 'Reliability') )
{
    Write-Host "Exporting reliability data..." -NoNewline
    Get-LHSReliabilityRecords | Export-Csv -Path $ExportPath\reliability.csv -NoTypeInformation -UseCulture -Encoding UTF8
    Write-Host "Done" -ForegroundColor Green
}
# Performance monitor export
#====================================================================
#perfmon /rel /report
