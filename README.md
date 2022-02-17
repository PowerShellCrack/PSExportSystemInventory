# PSExportSystemInventory
PowerShell script that exports System inventory such as hardware, missing drivers GPO, updates, etc


# Execute

Be sure to read the SYNOPSIS at top of script. Here are some examples:

_Exports all areas..._

```powershell
    .\ExportSystemInventory.ps1
```

_Exports all areas but exports to different location (c:\Temp\Exports)..._
```powershell
    .\ExportSystemInventory.ps1 -ExportPath c:\Temp\Exports
```

_Exports only updates which includes hotfixes._
```powershell
    .\ExportSystemInventory.ps1 -Category Updates
```

## Current items exported:
- MSINFO
- Bitlocker Information
- Firewall Information
- Applocker Effective Policy
- Local Administrators
- Missing Driver information
- SYSTEMINFO
- COMPUTERINFO
- software list
- services info
- list of installed features
- list of installed Windows capabilities
- Windows Defender definition versions
- list of installed hotfixes
- list of installed modern apps for users
- list of available modern apps for system
- list of installed FOD packages
- list of Windows update history
- group policies
- reliability data

## Outputs

__the script output:__

![HostOutput](/.images/hostoutput.png)


__the file export:__

![FolderExport](/.images/exportedfiles.png)


## Questions
-  What else should this script export?
- Is it beneficial to select an area to export?
