

#Global Variable
# this is created via RMM - New-Item -ItemType directory -Path C:\FWIInstall
$OutputFile = "C:\Users\Public\Documents\autoconfig\ErrorLog.txt"

#Required assembly
Add-Type -AssemblyName System.IO.Compression.FileSystem

#Ensure policy is set correctly 
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted -Force


#FunctionToUnzipFolder
function Unzip
{
    param([string]$zipfile, [string]$outpath)

    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfile, $outpath)
}

function RegistryCheck
{
    param([string]$RegKeyPath, [string]$RegValuePath, [String]$RegValue)

    $RegCheck = Get-ItemProperty -path $RegKeyPath -Name $RegValuePath | ForEach-Object {$_.$RegValuePath} 

    if($RegCheck -ne $RegValue)
    {
         Write-Output "FAIL -- $RegKeyPath\$RegValuePath has not been set correctly, please check manually" | Out-File -append -FilePath $OutputFile
    }
    
}



#Function to UnzipAllApplications
Function UnzipAllApplications
{
    Unzip "C:\Users\Public\Documents\autoconfig\AllApplications.zip" "C:\Users\Public\Documents\autoconfig"
}



#Functions for both Win 7 and 10
#----------------------------------------------------------------------------------------------------------------------------------------


function lavSettings

{
function enable-privilege {
 param(
  ## The privilege to adjust. This set is taken from
  ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
  [ValidateSet(
   "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
   "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
   "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
   "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
   "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
   "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
   "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
   "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
   "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
   "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
   "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
  $Privilege,
  ## The process on which to adjust the privilege. Defaults to the current process.
  $ProcessId = $pid,
  ## Switch to disable the privilege, rather than enable it.
  [Switch] $Disable
 )

 ## Taken from P/Invoke.NET with minor adjustments.
 $definition = @'
 using System;
 using System.Runtime.InteropServices;
  
 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
  
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }
  
  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

 $processHandle = (Get-Process -id $ProcessId).Handle
 $type = Add-Type $definition -PassThru
 $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
}

function ChangePermission {
    Param([string]$key)
    
    $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($key,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::takeownership)

    echo $key | get-member -MemberType Properties
    # You must get a blank acl for the key b/c you do not currently have access
    $acl = $regKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
    $owner = [System.Security.Principal.NTAccount]"Administrators"
    $acl.SetOwner($owner)
    $regKey.SetAccessControl($acl)

    # After you have set owner you need to get the acl with the permissions so you can modify it.
    $acl = $regKey.GetAccessControl()
    $person = [System.Security.Principal.NTAccount]"Administrators"
    $access = [System.Security.AccessControl.RegistryRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"

    $rule = New-Object System.Security.AccessControl.RegistryAccessRule($person,$access,$inheritance,$propagation,$type)
    $acl.SetAccessRule($rule)
    $regKey.SetAccessControl($acl)
    $regKey.Close()
}

# Exit this script if the video controller is not Intel
$query = "select pnpdeviceid from Win32_VideoController"
$match = "pci\\ven_8086" # Intel vender ID including regex escape '\' character
if((Get-WmiObject -query $query).pnpdeviceid -match $match){
    echo "Intel video found. Continuing"
} else {
    New-Item -Path "HKCU:\Software" -Name "LAV" -Force
    New-Item -Path "HKCU:\Software\LAV" -Name "Video" -Force
    New-Item -Path "HKCU:\Software\LAV\Video" -Name "HWAccel" -Force
    if([environment]::OSVersion.Version.Major -eq 10) {
        # Non-Intel video on Windows 10 - "DXVA2(Copy-Back)"
        Set-ItemProperty -Path "HKCU:\Software\LAV\Video\HWAccel" -Name "HWAccel" -Value 3 -Type Dword -Force
    } else {
        # Non-Intel video on Windows 7 - "DXVA2(Native)"
        Set-ItemProperty -Path "HKCU:\Software\LAV\Video\HWAccel" -Name "HWAccel" -Value 4 -Type Dword -Force
    }
    echo "No Intel video. Exiting"
    exit
}

# Changing ownership of registry keys.
ChangePermission -key "Software\Microsoft\DirectShow\Preferred"

# If running 64 bit OS...
ChangePermission -key "SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred"

echo "Administrators Group ownership privileges set."

# Begin registry modifications of newly available keys
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{000000FF-0000-0010-8000-00aa00389b71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{00000050-0000-0010-8000-00AA00389B71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{00000055-0000-0010-8000-00AA00389B71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{00001602-0000-0010-8000-00aa00389b71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{31435641-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{31435648-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{31435657-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{31564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{32564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
#Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{33564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{34363248-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{34363268-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{41564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{44495658-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{47504A4D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{5334504D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{5634504D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{58564944-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{64697678-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{64737664-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{7334706D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{7634706D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{78766964-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{e06d8026-db46-11cf-b4d1-00805f6cbbea}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{e06d802b-db46-11cf-b4d1-00805f6cbbea}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{e436eb80-524f-11ce-9f53-0020af0ba770}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\DirectShow\Preferred" -Name "{e436eb81-524f-11ce-9f53-0020af0ba770}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
if(Test-Path "HKLM:\SOFTWARE\Wow6432Node"){
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{000000FF-0000-0010-8000-00aa00389b71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{00000050-0000-0010-8000-00AA00389B71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{00000055-0000-0010-8000-00AA00389B71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{00001602-0000-0010-8000-00aa00389b71}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{31435641-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{31435648-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{31435657-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{31564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{32564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    #Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{33564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{34363248-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{34363268-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{41564D57-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{44495658-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{47504A4D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{5334504D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{5634504D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{58564944-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{64697678-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{64737664-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{7334706D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{7634706D-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{78766964-0000-0010-8000-00AA00389B71}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{e06d8026-db46-11cf-b4d1-00805f6cbbea}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{e06d802b-db46-11cf-b4d1-00805f6cbbea}" -Value "{E8E73B6B-4CB3-44A4-BE99-4F7BCB96E491}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{e436eb80-524f-11ce-9f53-0020af0ba770}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\DirectShow\Preferred" -Name "{e436eb81-524f-11ce-9f53-0020af0ba770}" -Value "{EE30215D-164F-4A92-A4EB-9D4C13390F9F}" -Force
}
# HKLM registry mods w/o ownership issues
New-Item -Path "HKLM:\Software" -Name "LAV" -Force
New-Item -Path "HKLM:\Software\LAV" -Name "Video" -Force
New-Item -Path "HKLM:\Software\LAV\Video" -Name "Formats" -Force
New-Item -Path "HKLM:\Software\LAV\Video\Formats" -Name "h264" -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\LAV\Video\Formats" -Name "h264" -Value 1 -Type Dword -Force
if(Test-Path "HKLM:\SOFTWARE\Wow6432Node"){
    New-Item -Path "HKLM:\Software\Wow6432Node" -Name "LAV" -Force
    New-Item -Path "HKLM:\Software\Wow6432Node\LAV" -Name "Video" -Force
    New-Item -Path "HKLM:\Software\Wow6432Node\LAV\Video" -Name "Formats" -Force
    New-Item -Path "HKLM:\Software\Wow6432Node\LAV\Video\Formats" -Name "h264" -Force
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\LAV\Video\Formats" -Name "h264" -Value 1 -Type Dword -Force
}

# HKCU registry mods
Push-Location
Set-Location HKCU:
New-Item -Path ".\Software" -Name "LAV" -Force
New-Item -Path ".\Software\LAV" -Name "Video" -Force
New-Item -Path ".\Software\LAV\Video" -Name "Formats" -Force
New-Item -Path ".\Software\LAV\Video" -Name "HWAccel" -Force
New-Item -Path ".\Software\LAV\Video" -Name "Output" -Force
New-Item -Path ".\Software\LAV\Video\Formats" -Name "h264" -Force

Set-ItemProperty -Path ".\Software\LAV\Video" -Name "DeintFieldOrder" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "DeintMode" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "DitherMode" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "DVDVideo" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "MSWMV9DMO" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "NumThreads" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "ResetSettings" -Value 2170154807 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "RGBRange" -Value 2 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "StreamAR" -Value 2 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "SWDeintMode" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "SWDeintOutput" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video" -Name "TrayIcon" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "8bps" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "bink" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "camstudio" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "camtasia" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "cinepak" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "dirac" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "dnxhd" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "dvvideo" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "ffv1" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "flash" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "flic" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "fraps" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "g2m" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "h261" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "h263" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "h263i" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "h264" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "hevc" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "huffyuv" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "icod" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "indeo3" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "indeo4" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "indeo5" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "jpeg2000" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "lagarith" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "loco" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "mjpeg" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "mpeg1" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "mpeg2" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "mpeg4" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "msmpeg4" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "msrle" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "msvideo1" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "png" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "prores" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "qpeg" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "qtrle" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "rpza" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "rv12" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "rv34" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "smackvid" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "snow" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "svq" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "theora" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "thp" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "truemotion" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "utvideo" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "v210/v410" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vc1" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vcr1" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vmnc" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vp6" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vp7" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vp8" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "vp9" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "wmv12" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "wmv3" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "zlib" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Formats" -Name "zmbv" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "dvd" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "h264" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "hevc" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "HWAccel" -Value 2 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "HWDeintHQ" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "HWDeintMode" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "HWDeintOutput" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "HWResFlags" -Value 7 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "mpeg2" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "mpeg4" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\HWAccel" -Name "vc1" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "ayuv" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "nv12" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "p010" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "p016" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "p210" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "p216" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "rgb24" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "rgb32" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "rgb48" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "uyvy" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "v210" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "v410" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "y410" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "y416" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "yuy2" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "yv12" -Value 1 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "yv16" -Value 0 -Type Dword -Force
Set-ItemProperty -Path ".\Software\LAV\Video\Output" -Name "yv24" -Value 1 -Type Dword -Force

Remove-ItemProperty -Path ".\Software\LAV\Video" -Name "DeintFieldOrder" -Force
Remove-ItemProperty -Path ".\Software\LAV\Video" -Name "DeintForce" -Force
Remove-ItemProperty -Path ".\Software\LAV\Video" -Name "DeintTreatAsProgressive" -Force

Pop-Location

echo "Registry changes completed."
}



Function SetupFirewall
{
#Change the workgroup to Signage
wmic computersystem where name="%computername%" call joindomainorworkgroup name="SIGNAGE"

#Turn off the firewall
netsh advfirewall set privateprofile state on
netsh advfirewall set publicprofile state on
netsh advfirewall set domainprofile state on

#Add firewall rules.  The image is set to use the "Work" profile by default

#Changed to 32-bit path, removed inbound rule
netsh advfirewall firewall add rule name="VLC" dir=out action=allow profile=any description="VLC" program="C:\Program Files (x86)\VideoLAN\VLC\vlc.exe"

#Changed to 32-bit path for all applications/subapplications, removed inbound rules
netsh advfirewall firewall add rule name="FWI Content Player" dir=out action=allow profile=any description="Content Player Signage" program="C:\Program Files (x86)\Four Winds Interactive\Content Player\Signage.exe"
netsh advfirewall firewall add rule name="FWI Content Player Service" dir=out action=allow profile=any description="Content Player Signage" program="C:\Program Files (x86)\Four Winds Interactive\Content Player\ContentPlayerService.exe"
netsh advfirewall firewall add rule name="FWI Content Player Monitor" dir=out action=allow profile=any description="Content Player Signage" program="C:\Program Files (x86)\Four Winds Interactive\Content Player\ContentPlayerMonitor.exe"
netsh advfirewall firewall add rule name="FWI Content Player External Player" dir=out action=allow profile=any description="Content Player Signage" program="C:\Program Files (x86)\Four Winds Interactive\Content Player\ExternalPlayer.exe"
netsh advfirewall firewall add rule name="FWI Content Player Movie Player" dir=out action=allow profile=any description="Content Player Signage" program="C:\Program Files (x86)\Four Winds Interactive\Shared Files\FwiMoviePlayer.exe"

#Socket Requests
netsh advfirewall firewall add rule name="FWI Reader ID Socket" dir=in action=allow profile=any protocol=TCP localport=10561

netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
netsh advfirewall firewall set rule group="Remote Desktop" new enable=Yes

netsh advfirewall firewall add rule name="FWI Multicast" dir=in action=allow profile=any protocol=udp localport=14000-14050
netsh advfirewall firewall add rule name="FWI Multicast" dir=out action=allow profile=any protocol=udp localport=14000-14050

# Cleaned up and consolidated rules - Removed 80/443 outbound as they are allow by default, added outbound UDP 70 to 71-75 range, corrected typo on FWI RMM9
netsh advfirewall firewall add rule name="FWI RMM1" dir=out action=allow profile=any protocol=udp localport=40000-41000
netsh advfirewall firewall add rule name="FWI RMM2" dir=out action=allow profile=any protocol=tcp localport=40000-40100
netsh advfirewall firewall add rule name="FWI RMM3" dir=out action=allow profile=any protocol=tcp localport=70
netsh advfirewall firewall add rule name="FWI RMM4" dir=out action=allow profile=any protocol=udp localport=70-75
netsh advfirewall firewall add rule name="FWI RMM5" dir=out action=allow profile=any protocol=udp localport=8002
netsh advfirewall firewall add rule name="FWI RMM6" dir=out action=allow profile=any protocol=tcp localport=8002
netsh advfirewall firewall add rule name="FWI RMM7" dir=out action=allow profile=any protocol=udp localport=70
netsh advfirewall firewall add rule name="FWI RMM8" dir=out action=allow profile=any protocol=tcp localport=80

# LEAVING THIS RULE 
netsh firewall set multicastbroadcastresponse ENABLE

# Disable Simple TCP Services
sc config "simptcp" start= disabled
sc stop "simptcp"

# Disable RDP Application
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /d 1 /F /t REG_DWORD
RegistryCheck "HKLM:SYSTEM\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "1" 

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /d 0 /F /t REG_DWORD
RegistryCheck "HKLM:SYSTEM\CurrentControlSet\Control\Remote Assistance" "fAllowToGetHelp" "0" 
}

Function TenAndSeven
{
#Disable Balloon Tips
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnableBalloonTips /d 0 /t REG_DWORD /F
RegistryCheck "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "EnableBalloonTips" "0" 

REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoTrayItemsDisplay /d 1 /F /t REG_DWORD
RegistryCheck "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "NoTrayItemsDisplay" "1"

#FWI background
REG ADD "HKCU\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Users\Public\Pictures\fwi_background.png" /f
RegistryCheck "HKCU:Control Panel\Desktop" "Wallpaper" "C:\Users\Public\Pictures\fwi_background.png"
%SystemRoot%\System32\RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True



#Remove Startup files
Remove-Item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\" -Include * -Recurse
Remove-Item "C:\Users\$env:username\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" -Include * -Recurse


#hideicons
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideIcons /d 1 /t REG_DWORD /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideIcons" "1" 

#NEED CHECK
#AutoReboot BSOD
#---------------------------------------------
wmic recoveros set AutoReboot = True
wmic recoveros set WriteToSystemLog = True


#Daily Reboot
#----------------------------------------------
SCHTASKS.EXE /CREATE /F /SC DAILY /TN "FWI reboot" /ST 02:30:00 /SD 01/01/2000 /TR "c:\windows\system32\shutdown.exe -r -f -t 10" /RU SYSTEM

#Power Settings
#---------------------------------------------------
powercfg -setactive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 003
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 000
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 000
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c fea3413e-7e05-4911-9a71-700331f1c294 0e796bdb-100d-47d6-a2d5-f7d2daa51f51 000
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 000
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0
powercfg -setacvalueindex 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0
powercfg -hibernate OFF
POWERCFG /SETACVALUEINDEX SCHEME_CURRENT SUB_VIDEO VIDEODIM 0

#WMP First Run Wizard disabled
REG ADD HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences /F /V AcceptedEULA /T REG_DWORD /D 1
REG ADD HKLM\SOFTWARE\Microsoft\MediaPlayer\Preferences /F /V FirstTime /T REG_DWORD /D 1
REG ADD HKLM\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer /F /V GroupPrivacyAcceptance /T REG_DWORD /D 1
RegistryCheck "HKLM:SOFTWARE\Microsoft\MediaPlayer\Preferences" "AcceptedEula" "1"
RegistryCheck "HKLM:SOFTWARE\Microsoft\MediaPlayer\Preferences" "FirstTime" "1"
RegistryCheck "HKLM:SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" "GroupPrivacyAcceptance" "1"

#Disable RDP and RDC
$registryPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$Name = "fDenyTSConnections"
$value = "1"
New-ItemProperty -Path $registryPath -Name $name -Value $value ` -PropertyType DWORD -Force | Out-Null
RegistryCheck "HKLM:\System\CurrentControlSet\Control\Terminal Server" "fDenyTSConnections" "1"

# Adding Registry key to remove "Allow Remote Assistance" from System Properties and setting to 0.
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fAllowToGetHelp –Force 
$registryPath1 = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
$Name1 = "fAllowToGetHelp"
$value1 = "0"
New-ItemProperty -Path $registryPath1 -Name $name1 -Value $value1 ` -PropertyType DWORD -Force | Out-Null
RegistryCheck "HKLM:\System\CurrentControlSet\Control\Terminal Server" "fAllowToGetHelp" "0"

#Remove Default Admin Share
REG ADD "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" /V AutoShareWks /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks" "0"

#Change Control Panel to Small Icons
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" /F /V AllItemsIconView /T REG_DWORD /D 1
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /F /V ForceClassicControlPanel /T REG_DWORD /D 1
RegistryCheck "HKCU:Software\Microsoft\Windows\CurrentVersion\Explorer\ControlPanel" "AllItemsIconView" "1"
RegistryCheck "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "ForceClassicControlPanel" "1"


#PowerButtonAction
REG ADD "HKCU\Software\Policies\Microsoft\Windows\Explorer" /F /V PowerButtonAction /T REG_DWORD /D 4
RegistryCheck "HKCU:Software\Policies\Microsoft\Windows\Explorer" "PowerButtonAction" "4"

#Disable Tablet INput Tab
REG ADD "HKCU\Software\Microsoft\TabletTip\1.7" /F /V EnableEdgeTarget /T REG_DWORD /D 0
RegistryCheck "HKCU:Software\Microsoft\TabletTip\1.7" "EnableEdgeTarget" "0"

}
#--------------------------------------------------------------------------------------------------------------------------------------------

#Windows 7 Functions
#--------------------------------------
Function WinUpdateSettings
{
#Windows Update Time
REG ADD "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" /v ScheduledInstallDay /d 4 /t REG_DWORD /F
RegistryCheck "HKLM:Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" "ScheduledInstallDay" "4"

}

Function DesktopGadgets
{
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" /V TurnOffSidebar /d 1 /T REG_DWORD /F
RegistryCheck "HKCU:Software\Microsoft\Windows\CurrentVersion\Policies\Windows\Sidebar" "TurnOffSidebar" "1"

}

Function ActionCenter {

reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAHealth /t REG_DWORD /d 1 /F
RegistryCheck "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" "HideSCAHealth" "1"
}

Function pageFile
{
$computersys = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges;
$computersys.AutomaticManagedPagefile = $True;
$computersys.Put();
}


Function toggleAutohideRegistrySettings($enable)
{

$autoHideSettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects2";
$autoHideValueName = "Settings";


    $key = Get-ItemProperty -Path $autoHideSettingsPath -Name $autoHideValueName;   

    Write-Host "key is: " + $key
    if($enable)
    {
        $key.$autoHIdeValueName[8] = $key.$autoHideValueName[8] -bor 3;

    }else{
        $key.$autoHIdeValueName[8] = $key.$autoHideValueName[8] -band 3;    
    }

    Set-ItemProperty -Path $autoHideSettingsPath -Name $autoHideValueName -Value $key.$autoHideValueName -Force;

    Stop-Process -name "explorer"
    Start-Sleep -Seconds 3
    Start-Process -name "explorer"
}






#--------------------------------------

#Windows 10 Functions
#--------------------------------------

#Windows CU Lockdown Function
Function CULockdown
{
#Disable shared updates (170329)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /V SystemSettingsDownloadMode /T REG_DWORD /D 3 /F
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /V DODownloadMode /D 0 /T REG_DWORD /F
RegistryCheck "HKCU:Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" "SystemSettingsDownloadMode" "3"
RegistryCheck "HKLM:Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" "DODownloadMode" "0"

#Disables Cortona
New-Item -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\' -Name 'Windows Search' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search' -Name 'AllowCortana' -PropertyType DWORD -Value '0' -Force | Out-Null
#Restart Explorer to change it immediately     
Stop-Process -name explorer

#Disable Show Touch Keyboard Button
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\TabletTip\1.7" /V "TipbandDesiredVisibility" /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:\Software\Microsoft\TabletTip\1.7" "TipbandDesiredVisibility" "0"

#Enable Autohide in Tablet mode
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /T REG_DWORD /D 1 /F


#Let Websites provide locally relvant content by accessing my langage list (Off)
REG ADD "HKCU\Control Panel\International\User Profile" /V HttpAcceptLanguageOptOut /T REG_DWORD /D 1 /F
RegistryCheck "HKCU:Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" "1"

#Turn on SmartScreen Filter to check web content (URLs) that Windows Store apps use (Off)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /V EnableWebContentEvaluation /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" "0"


#Disable banner ads in file explorer (Windows Pro)
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowSyncProviderNotifications /T REG_DWORD /D 0 /F

#Disable tips and tricks
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V SoftLandingEnabled /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" "SoftLandingEnabled" "0"

#Notifications

#Show app notifications (Off)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" /V ToastEnabled /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" "ToastEnabled" "0"

# Quiet Hours (On)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /V NOC_GLOBAL_SETTING_TOASTS_ENABLED /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_TOASTS_ENABLED" "0"

#Show notifications on lock screen (Off)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /V NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_ALLOW_TOASTS_ABOVE_LOCK" "0"

#Show alarms, reminders, etc lockscreen (Off)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /V NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" "NOC_GLOBAL_SETTING_ALLOW_CRITICAL_TOASTS_ABOVE_LOCK" "0"


#Hide notifications while presenting (On)
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings" /V NOC_GLOBAL_SETTING_SUPRESS_TOASTS_WHILE_DUPLICATING /T REG_DWORD /D 1 /F


#Disable Notification Center (On)
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V DisableNotificationCenter /T REG_DWORD /D 1 /F
RegistryCheck "HKCU:SOFTWARE\Policies\Microsoft\Windows\Explorer" "DisableNotificationCenter" "1"
REG ADD "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v MaintenanceDisabled /T REG_DWORD /D 1 /F

#Privacy option (Off)
REG ADD "HKCU\SOFTWARE\Microsoft\Input\TIPC" /V Enabled /T REG_DWORD /D 0 /F
RegistryCheck "HKCU:SOFTWARE\Microsoft\Input\TIPC" "Enabled" "0"

#Disable toast notifications and lock screen toast notifications (On) - Does not affect system nofications, use Disable_Senders powershell script for that
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /V NoToastApplicationNotification /T REG_DWORD /D 1 /F
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /V NoToastApplicationNotificationOnLockScreen /T REG_DWORD /D 1 /F
RegistryCheck "HKCU:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotification" "1"
RegistryCheck "HKCU:SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" "NoToastApplicationNotificationOnLockScreen" "1"
}




Function toggleAutohideRegistrySettingswin10($enable)
{

    $autoHideSettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3";
    $autoHideValueName = "Settings";

    $key = Get-ItemProperty -Path $autoHideSettingsPath -Name $autoHideValueName;   

    Write-Host "key is: " + $key
    if($enable)
    {
        $key.$autoHIdeValueName[8] = $key.$autoHideValueName[8] -bor 1;

    }else{
        $key.$autoHIdeValueName[8] = $key.$autoHideValueName[8] -band 0;    
    }

    Set-ItemProperty -Path $autoHideSettingsPath -Name $autoHideValueName -Value $key.$autoHideValueName;
}

Function LMLockdown
{
#[Group Policy Name] [Min. Applicable Windows Version] [(Setting)]
#Allow Telemetry (None)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /V AllowTelemetry /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" "0"

#Turn off the advertising ID (Off)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AdvertisingInfo" /V DisabledByGroupPolicy /T REG_DWORD /D 1 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AdvertisingInfo" "DisabledByGroupPolicy" "1"

#Turn off location (Off)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\LocationAndSensors" /V DisableLocation /T REG_DWORD /D 1 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\LocationAndSensors" "DisableLocation" "1"

#Allow input personalization 1507 (Off)
REG ADD "HKLM\Software\Policies\Microsoft\InputPersonalization" /V AllowInputPersonalization /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\InputPersonalization" "AllowInputPersonalization" "0"

#Do not show feedback notifications 1511 (On)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /V DoNotShowFeedbackNotifications /T REG_DWORD /D 1 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\DataCollection" "DoNotShowFeedbackNotifications" "1"


#Let Windows apps access account information 1607 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessAccountInfo /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessAccountInfo" "2"

#Let Windows apps access call history 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessCallHistory /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCallHistory" "2"

#Let Windows apps access contacts 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessContacts /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessContacts" "2"

#Let Windows apps access email 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessEmail /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessEmail" "2"

#Let Windows apps access location 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessLocation /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessLocation" "2"

#Let Windows apps access messaging 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessMessaging /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMessaging" "2"

#Let Windows apps access motion 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessMotion /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMotion" "2"

#Let Windows apps access notifications 1607 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessNotifications /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMotion" "2"

#Let Windows apps access the calendar 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessCalendar /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCalendar" "2"

#Let Windows apps access the camera 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessCamera /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessCamera" "2"

#Let Windows apps access the microphone 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessMicrophone /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessMicrophone" "2"

#Let Windows apps access trusted devices 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessTrustedDevices /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessTrustedDevices" "2"

#Let Windows apps control radios 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsAccessRadios /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsAccessRadios" "2"

#Let Windows apps sync with devices 1511 (Force Deny)
REG ADD "HKLM\Software\Policies\Microsoft\Windows\AppPrivacy" /V LetAppsSyncWithDevices /T REG_DWORD /D 2 /F
RegistryCheck "HKLM:Software\Policies\Microsoft\Windows\AppPrivacy" "LetAppsSyncWithDevices" "2"

#Allow edge swipe (Off)
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /V AllowEdgeSwipe /T REG_DWORD /D 0 /F


#[Non-GP Registry edit] [(Setting)]
#Let apps on my other devices open apps and continue experiences on this device (Off)
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /V UserAuthPolicy /T REG_DWORD /D 0 /f
RegistryCheck "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" "UserAuthPolicy" "0"

#Let apps on my other devices use Bluetooth to open apps and continue experiences on this device (Off)
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" /V BluetoothPolicy /T REG_DWORD /D 0 /f
RegistryCheck "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\SmartGlass" "BluetoothPolicy" "0"

#Disable ICS/Mobile Hotspot (Off)
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /V NC_ShowSharedAccessUI /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:SOFTWARE\Policies\Microsoft\Windows\Network Connections" "NC_ShowSharedAccessUI" "0"

#Offline maps automatically update (Off)
REG ADD "HKLM\SYSTEM\Maps" /V AutoUpdateEnabled /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:SYSTEM\Maps" "AutoUpdateEnabled" "0"

#Disable Wifi sense on Windows 10 (Disabled) This is only applicable pre 1607
REG ADD "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /V AutoConnectAllowedOEM /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" "AutoConnectAllowedOEM" "0"

#Disable the Win10 first logon animation for new users
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V EnableFirstLogonAnimation /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableFirstLogonAnimation" "0"
}

Function unpintiles {
#Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
		$data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
		$data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
		Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
}

Function Remove10Bloat
{
 #NUKE BLOAT

 
 Get-AppxPackage *Microsoft.3dbuilder* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.Asphalt8Airborne* | Remove-AppxPackage
 Get-AppxPackage *microsoft.windowscommunicationsapps* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage
 Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.DrawboardPDF* | Remove-AppxPackage
 Get-AppxPackage *Facebook* | Remove-AppxPackage
 Get-AppxPackage *BethesdaSoftworks.FalloutShelter* | Remove-AppxPackage
 Get-AppxPackage *FarmVille2CountryEscape* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage
 Get-AppxPackage *officehub* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage
 Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
 Get-AppxPackage *Wallet* | Remove-AppxPackage
 Get-AppxPackage *MinecraftUWP* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.BingFinance* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage
 Get-AppxPackage *Netflix* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage
 Get-AppxPackage *OneNote* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage
 Get-AppxPackage *PandoraMediaInc* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.People* | Remove-AppxPackage
 Get-AppxPackage *CommsPhone* | Remove-AppxPackage
 Get-AppxPackage *windowsphone* | Remove-AppxPackage
 Get-AppxPackage *Photos* | Remove-AppxPackage
 Get-AppxPackage *flaregamesGmbH.RoyalRevolt2* | Remove-AppxPackage
 Get-AppxPackage *WindowsScan* | Remove-AppxPackage
 Get-AppxPackage *AutodeskSketchBook* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage
 Get-AppxPackage *bingsports* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage
 Get-AppxPackage *WindowsStore* | Remove-AppxPackage
 Get-AppxPackage *Office.Sway* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage
 Get-AppxPackage *Twitter* | Remove-AppxPackage
 Get-AppxPackage *Microsoft3DViewer* | Remove-AppxPackage
 Get-AppxPackage *soundrecorder* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage
 Get-AppxPackage *XboxApp* | Remove-AppxPackage
 Get-AppxPackage *XboxOneSmartGlass* | Remove-AppxPackage
 Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage
 Get-AppxPackage *MarchofEmpires* | Remove-AppxPackage
 Get-AppxPackage *BubbleWitch3* | Remove-AppxPackage
 Get-AppxPackage *XboxGame* | Remove-AppxPackage
 Get-AppxPackage *Spotify* | Remove-AppxPackage
 Get-AppxPackage *DisneyMagicKingdoms* | Remove-AppxPackage
 Get-AppxPackage *Xbox.TCUI* | Remove-AppxPackage
 Get-AppxPackage *XboxGameOverlay* | Remove-AppxPackage
 Get-AppxPackage *Paint3D* | Remove-AppxPackage
 Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
 Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
 Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
 Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
 Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
 Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
 Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
 Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
 Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
 Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
 Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
 Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
 Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
 Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
 Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
 Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
 Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
 Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
 Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
 Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
 Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
 Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
 Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
 Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
 Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage



}
Function DPI
{
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "Win8DpiScaling" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v "AppliedDpi" /t REG_DWORD /d 96 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LogPixels" /t REG_DWORD /d 96 /f
RegistryCheck "HKCU:Control Panel\Desktop" "Win8DpiScaling" "1"
RegistryCheck "HKCU:Control Panel\Desktop\WindowMetricS" "AppliedDpi" "96"
RegistryCheck "HKCU:Control Panel\Desktop" "LogPixels" "96"
}

Function ActiveUpdateHours
{
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\tzautoupdate\time zone" /V "IsActiveHoursEnabled" /T REG_DWORD /D 0 /F
RegistryCheck "HKLM:SYSTEM\CurrentControlSet\Services\tzautoupdate\time zone" "IsActiveHoursEnabled" "0"
}

Function DisableEdgeUI
{
REG DELETE "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\EdgeUI\ALLOWEDGESWIPE" /F

REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v AllowEdgeSwipe /d 0 /t REG_DWORD /F
RegistryCheck "HKLM:SOFTWARE\Policies\Microsoft\Windows\EdgeUI" "AllowEdgeSwipe" "0"
}


Function win10toggleAutohideRegistrySettings($enable)
{
    $key = Get-ItemProperty -Path $autoHideSettingsPath -Name $autoHideValueName;   
    Write-Host "key is: " + $key
    if($enable)
    {
        $key.$autoHIdeValueName[8] = $key.$autoHideValueName[8] -bor 1;
    }else{
        $key.$autoHIdeValueName[8] = $key.$autoHideValueName[8] -band 0;    
    }
    Set-ItemProperty -Path $autoHideSettingsPath -Name $autoHideValueName -Value $key.$autoHideValueName;
}
$autoHideSettingsPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3";
$autoHideValueName = "Settings";
toggleAutohideRegistrySettings($true)


#--------------------------------------


#Install Functions
#-----------------------------------------

Function AdobeReader
{
    cmd.exe /c "C:\Users\Public\Documents\autoconfig\AllApplications\AReader\install.cmd"

}

Function LAVFilters
{

cmd.exe /c "C:\Users\Public\Documents\autoconfig\AllApplications\LAV\Install.cmd"
    
}


Function VLC
{

cmd.exe /c "C:\Users\Public\Documents\autoconfig\AllApplications\VLC\Install.cmd"
    
}

#-------------------------------------------

#Identifies the OS and stores in variable
$OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName

#checks against OS
If($OSVersion -like "*10*")
{
    Unzipallapplications
    win10toggleAutohideRegistrySettings($true)
    LAVFilters
    AdobeReader
    VLC
    SetupFirewall
    pageFile
    unpintiles
    TenAndSeven
    CULockdown
    hideIcons
    LmLockdown
    Remove10Bloat
    DPI
    DisableEdgeUI
    ActiveUpdateHours
    lavSettings
	
	restart-computer -force
   
}


elseif ( $OSVersion -like "*Embedded*" -or $OSVersion -like "*7*") 
{

        Unzipallapplications
        LAVFilters
        AdobeReader
        VLC
        pageFile
        toggleAutohideRegistrySettings($true)
        WinUpdateSettings
        DesktopGadgets
        ActionCenter
        hideIcons
        TenAndSeven
        SetupFirewall
        lavSettings
		
		restart-computer -force

    }
    

else
{
write-host "Your $OSVersion OS is not supported, the script will now terminate",0,"ERROR"
#$a = new-object -comobject wscript.shell
#$b = $a.popup("Your $OSVersion OS is not supported, the script will now terminate",0,"ERROR")
}