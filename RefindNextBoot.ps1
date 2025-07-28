#Requires -Version 2
<#
.Synopsis
 Get and Set the PreviousBoot efivar that is read by rEFInd.
.DESCRIPTION
 Modify the PreviousBoot EFI variable that is read and modified by the rEFInd bootloader.
 If rEFInd is properly configured, modifying this variable to a substring
 of an available entry will boot the entry on the next boot.
.PARAMETER action
 The action to take upon running the script. One of 'none' (default), 'get'
 or 'set'. Use `none` if you just want to source the script.
.PARAMETER value
 A value to set if $action = 'set'.
.EXAMPLE
 & RefindNextBoot.ps1 get
.EXAMPLE
 & RefindNextBoot.ps1 set "EFI\arch\vmlinuz-linux"
.NOTES
 Author: Fixed version based on correct rEFInd PreviousBoot variable format
 Format: 4 bytes (07 00 00 00) + UTF-16 string + 4 bytes (20 00 00 00)
#>
Param(
 [Parameter()]
 [ValidateSet('set', 'get', 'none')]
 [String]$action = 'none',
 [Parameter()]
 [String]$value = ''
)

# Embedded C# script with corrected EFI variable handling based on rEFInd format
$csharpCode = @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public class RefindNextBoot
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();

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
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    internal const string SE_SYSTEM_ENVIRONMENT_NAME = "SeSystemEnvironmentPrivilege";

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern UInt32 GetFirmwareEnvironmentVariableA(string lpName, string lpGuid, IntPtr pBuffer, UInt32 nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    static extern bool SetFirmwareEnvironmentVariableA(string lpName, string lpGuid, IntPtr pBuffer, UInt32 nSize);

    private static bool SetPrivilege()
    {
        try
        {
            bool retVal;
            TokPriv1Luid tp;
            IntPtr hproc = GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = LookupPrivilegeValue(null, SE_SYSTEM_ENVIRONMENT_NAME, ref tp.Luid);
            retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
            return retVal;
        }
        catch (Exception)
        {
            return false;
        }
    }

    public static string Get()
    {
        if (!RefindNextBoot.SetPrivilege())
        {
            return "Error: Unable to set privilege";
        }

        UInt32 size = 1024;
        byte[] buffer = new byte[size];
        UInt32 ret;
        GCHandle handle = default(GCHandle);
        try
        {
            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            IntPtr pointer = handle.AddrOfPinnedObject();
            ret = GetFirmwareEnvironmentVariableA("PreviousBoot", "{36d08fa7-cf0b-42f5-8f14-68df73ed3740}", pointer, size);

            if (ret > 0)
            {
                // Based on hex dump: direct UTF-16 string with null terminator
                string result = Encoding.Unicode.GetString(buffer, 0, (int)ret);
                // Remove null terminators
                result = result.TrimEnd('\0');

                // Extract the useful substring that should be passed to set command
                if (result.Contains("Microsoft"))
                {
                    return "Microsoft";
                }
                else if (result.Contains("EFI\\arch\\vmlinuz-linux"))
                {
                    return "EFI\\arch\\vmlinuz-linux";
                }
                else
                {
                    // For unknown entries, return the full string
                    return result;
                }
            }
        }
        finally
        {
            if (handle.IsAllocated)
            {
                handle.Free();
            }
        }

        if (ret == 0)
        {
            string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            return "Error: " + errorMessage;
        }

        return "Error: Unknown error occurred";
    }

    public static string Set(string efivar)
    {
        if (!RefindNextBoot.SetPrivilege())
        {
            return "Error: Unable to set privilege";
        }

        // Based on actual hex dump: just UTF-16 string with trailing space + null terminator
        // Add trailing space if not present
        if (!efivar.EndsWith(" "))
        {
            efivar += " ";
        }

        // Convert string to UTF-16 bytes (includes null terminator)
        byte[] buffer = Encoding.Unicode.GetBytes(efivar + "\0");
        UInt32 size = (uint)buffer.Length;

        bool success;
        GCHandle handle = default(GCHandle);
        try
        {
            handle = GCHandle.Alloc(buffer, GCHandleType.Pinned);
            IntPtr pointer = handle.AddrOfPinnedObject();
            success = SetFirmwareEnvironmentVariableA("PreviousBoot", "{36d08fa7-cf0b-42f5-8f14-68df73ed3740}", pointer, size);
        }
        finally
        {
            if (handle.IsAllocated)
            {
                handle.Free();
            }
        }

        if (success)
        {
            return "Successfully set PreviousBoot to: " + efivar.TrimEnd();
        }
        else
        {
            string errorMessage = new Win32Exception(Marshal.GetLastWin32Error()).Message;
            return "Error setting variable: " + errorMessage;
        }
    }
}
"@

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Get the directory where the exe is located
$exeDir = if ($MyInvocation.MyCommand.Path) {
    Split-Path -Path $MyInvocation.MyCommand.Path -Parent
} else {
    $PWD.Path
}
$outputFile = Join-Path $exeDir "RefindNextBoot.txt"

# Request elevation if not running as administrator
if (-not (Test-Administrator)) {
    # Build arguments string
    $arguments = ""
    if ($action -ne 'none') {
        $arguments += " -action $action"
    }
    if ($value -ne '') {
        $arguments += " -value `"$value`""
    }

    try {
        # Re-run elevated with current directory preserved
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = "powershell.exe"
        $psi.Arguments = "-ExecutionPolicy Bypass -Command `"Set-Location '$exeDir'; & '$($MyInvocation.MyCommand.Path)' $arguments`""
        $psi.UseShellExecute = $true
        $psi.Verb = "RunAs"

        [System.Diagnostics.Process]::Start($psi) | Out-Null
        Write-Output "Elevated process launched. Check $outputFile for results."
        exit 0
    }
    catch {
        Write-Output "Failed to elevate privileges: $($_.Exception.Message)"
        exit 1
    }
}

# Inject the C# script into the PowerShell Session
Add-Type -Language CSharp -TypeDefinition $csharpCode

# Execute based on action parameter and write to file
try {
    $result = ""
    if ($action -eq 'get') {
        $result = [RefindNextBoot]::Get()
    }
    elseif ($action -eq 'set') {
        $result = [RefindNextBoot]::Set($value)
    }
    else {
        $result = @"
Available actions: get, set
Example: RefindNextBoot.exe -action set -value "EFI\arch\vmlinuz-linux"

Note: Based on your hex dump, try these values:
- For Arch: "EFI\arch\vmlinuz-linux"
- For Windows: "Microsoft" or "Windows"

The value should match what rEFInd shows in its boot menu.
"@
    }

    # Always write result to output file
    $result | Out-File -FilePath $outputFile -Encoding UTF8 -Force

    # Also display to console if running elevated
    Write-Output $result
}
catch {
    $errorMsg = "Error: $($_.Exception.Message)"
    $errorMsg | Out-File -FilePath $outputFile -Encoding UTF8 -Force
    Write-Output $errorMsg
}
