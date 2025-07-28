# RefindNextBoot Dual-Boot Toolkit

A cross-platform toolkit for controlling boot entries in rEFInd bootloader. Switch between Windows and Linux without manually selecting from the rEFInd boot menu.

## Package Contents

- **`RefindNextBoot.exe`** - Windows executable for setting boot entries
- **`refind-next-boot.sh`** - Linux bash script for setting boot entries
- **`README.md`** - This documentation

## Overview

This toolkit allows you to:
- Set which OS to boot next from either Windows or Linux
- Automatically reboot to the other OS without user interaction
- Query the current boot entry from either OS

## Requirements

- **UEFI-based system** (not legacy BIOS)
- **rEFInd bootloader** properly installed and configured
- **Administrator/root privileges** on both operating systems

## Windows Tool Output Behavior

The Windows executable handles output differently depending on how it's run:

### When run from Command Prompt/PowerShell with Administrator privileges:
- Output appears directly in the terminal
- Immediate feedback for commands

### When run via shortcuts:
- Automatically requests Administrator privileges via UAC
- **Output is saved to `RefindNextBoot.txt`** in the same directory as the executable
- Check this text file for command results and any error messages

### When double-clicked without arguments:
- Window dissapears immediately (requires `-action get` or `-action set` parameters)
- Use shortcuts with proper arguments instead

**Important:** Always check `RefindNextBoot.txt` for the actual results when using shortcuts.

## Quick Start Guide

### 1. Find Your Boot Entry Strings

#### From Linux (to find the Linux string):
```bash
# Boot into Linux, then run:
sudo ./refind-next-boot.sh get
```
**Example output:** `EFI\arch\vmlinuz-linux`

#### From Windows (to find the Windows string):
```cmd
# Run from Administrator Command Prompt:
RefindNextBoot.exe -action get
```
**Example output:** `Microsoft`

### 2. Test the Strings

#### Set Windows as Next Boot (from Linux):
```bash
sudo ./refind-next-boot.sh "Microsoft"
sudo reboot
```

#### Set Linux as Next Boot (from Windows):
```cmd
# From Administrator Command Prompt:
RefindNextBoot.exe -action set -value "EFI\arch\vmlinuz-linux"

# OR use a shortcut with target: RefindNextBoot.exe -action set -value "EFI\arch\vmlinuz-linux"
# OR whatever value you got when you ran "sudo ./refind-next-boot.sh get" on linux
# Check RefindNextBoot.txt for confirmation
```

## Common Boot Entry Strings

The exact strings depend on your system configuration. Here are common examples:

### Windows:
- `Microsoft`
- `Windows`
- `bootmgfw`

### Linux Distributions:
- **Arch Linux:** `EFI\arch\vmlinuz-linux`
- **Ubuntu:** `EFI\ubuntu\vmlinuz`
- **Fedora:** `EFI\fedora\vmlinuz`
- **Pop!_OS:** `systemd-boot`
- **Generic:** `vmlinuz` or `linux`


## Troubleshooting

### Finding the Correct Boot Strings

If the obvious strings don't work:

1. **Boot into each OS and use the get command**
2. **For Windows: Always check `RefindNextBoot.txt` for the actual output**
3. **Try shorter substrings:**
   - Instead of `EFI\arch\vmlinuz-linux`, try `arch`
   - Instead of `Microsoft EFI boot`, try `Microsoft`

### Common Issues

#### Windows: "No output visible"
- **Check `RefindNextBoot.txt`** in the same directory as the executable
- This file contains all command results when run via shortcuts
- Double-clicking the exe without arguments does nothing (use shortcuts with proper arguments)

#### "Access Denied" (Windows):
- Run Command Prompt as Administrator
- Or allow UAC prompt when double-clicking

#### "Permission denied" (Linux):
- Always use `sudo` with the script

#### Boot entry doesn't work:
- Use the `get` command to see actual values
- Try different substrings
- Check `RefindNextBoot.txt` for error messages

## Technical Details

### How It Works:
- Modifies the `PreviousBoot` EFI variable (GUID: `36d08fa7-cf0b-42f5-8f14-68df73ed3740`)
- rEFInd reads this variable to determine the default boot entry
- Uses substring matching - any part of the boot entry name/path works

### File Locations:
- **Windows output:** `RefindNextBoot.txt` (same directory as executable)
- **Linux EFI variables:** `/sys/firmware/efi/efivars/`

## Credits

Based on original work by:
- **Denys Pavlov** (`<me@denys.me>`) - PowerShell script framework
- **Darkhogg** - Original rEFInd EFI variable concept (https://gist.github.com/Darkhogg/82a651f40f835196df3b1bd1362f5b8c)
- **ps2exe** for conversion of powershell script into exe (https://github.com/MScholtes/PS2EXE)

## Quick Reference

| Task | Windows Command | Linux Command |
|------|----------------|---------------|
| **Get current boot entry** | `RefindNextBoot.exe -action get`<br/>*(Check RefindNextBoot.txt if using shortcuts)* | `sudo ./refind-next-boot.sh get` |
| **Set to Windows** | `RefindNextBoot.exe -action set -value "Microsoft"` | `sudo ./refind-next-boot.sh "Microsoft"` |
| **Set to Linux** | `RefindNextBoot.exe -action set -value "EFI\arch\vmlinuz-linux"` | `sudo ./refind-next-boot.sh "EFI\\arch\\vmlinuz-linux"` |

**Remember:** On Windows, check `RefindNextBoot.txt` for results when using shortcuts!)


**Features:**
- Automatically requests Administrator privileges via UAC
- Saves results to `RefindNextBoot.txt` for reference
- Handles elevation and privilege management automatically

## Creating Shortcuts and Automation

### Windows Desktop Shortcut (Reboot to Linux):
1. **Right-click desktop** → New → Shortcut
2. **Target:** `C:\Path\To\RefindNextBoot.exe -action set -value "EFI\arch\vmlinuz-linux"`
3. **Name:** "Reboot to Linux"
4. **Right-click shortcut** → Properties → Advanced → Run as administrator

### Linux Desktop Shortcut (Reboot to Windows):
Create `reboot-to-windows.desktop` and copy it to ~/.local/share/applications/:
```ini
[Desktop Entry]
Version=1.0
Type=Application
Name=Reboot to Windows
Comment=Set next boot to Windows and reboot
Exec=bash -c 'pkexec /path/to/refind-next-boot.sh "Microsoft" && systemctl reboot'
Icon=windows
Terminal=false
Categories=System;
```

# Dialogs

You can change the Exec value as follows to get a dialog when clicking the shortcut.

make sure kdialog is installed first (KDE) or zenity (Gnome), or you can try notify-send if all else fails.

```Exec=bash -c 'pkexec /home/earl/refind-next-boot.sh "Microsoft" && kdialog --msgbox "Boot entry has been set to Windows. Next restart will go to Windows."'```

## Troubleshooting

### Finding the Correct Boot Strings

If the obvious strings don't work, try these methods:

1. **Boot into each OS and use the get command**
2. **Check your rEFInd boot menu text**
3. **Examine your EFI partition structure:**
   ```bash
   # Linux:
   ls -la /boot/EFI/
   
   # Windows:
   mountvol S: /s
   dir S:\EFI\
   ```
4. **Try shorter substrings:**
   - Instead of `EFI\arch\vmlinuz-linux`, try `arch`
   - Instead of `Microsoft EFI boot`, try `Microsoft`


### Testing Safely

1. **Always test the get command first**
2. **Note the current value before changing it**
3. **Test with a single reboot before creating automation**
4. **Keep a recovery USB handy when testing**

## Technical Details

### How It Works:
- Modifies the `PreviousBoot` EFI variable (GUID: `36d08fa7-cf0b-42f5-8f14-68df73ed3740`)
- rEFInd reads this variable to determine the default boot entry
- Uses substring matching - any part of the boot entry name/path works
- Stores data in UTF-16 format as required by EFI specification

### File Locations:
- **Windows output:** `RefindNextBoot.txt` (same directory as .exe)
- **Linux EFI variables:** `/sys/firmware/efi/efivars/`
- **EFI partition:** Usually `/boot/EFI/` (Linux) or `S:\EFI\` (Windows)

### Security:
- Requires elevated privileges on both platforms
- Only modifies boot selection (reversible)
- No network access or external dependencies
- Works entirely with local EFI variables

## Version Information

- **Windows Tool:** PowerShell with embedded C# for EFI variable access
- **Linux Script:** Bash with standard Unix tools (iconv, chattr)
- **Compatibility:** Tested on Windows 10/11 and modern Linux distributions
- **Requirements:** UEFI firmware, rEFInd bootloader

## License

This toolkit is provided as-is for educational and personal use. Always test in a safe environment before using on production systems.
