#!/bin/bash

# rEFInd next boot script for Linux
# Usage: sudo ./refind-next-boot.sh "Microsoft"
#        sudo ./refind-next-boot.sh "EFI\\arch\\vmlinuz-linux"

EFIVAR_PATH="/sys/firmware/efi/efivars/PreviousBoot-36d08fa7-cf0b-42f5-8f14-68df73ed3740"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: This script must be run as root (use sudo)"
    exit 1
fi

# Check if efivarfs is available
if [ ! -d "/sys/firmware/efi/efivars/" ]; then
    echo "Error: EFI variables not available. Are you running on a UEFI system?"
    exit 1
fi

# Function to get current boot entry
get_current() {
    if [ ! -f "$EFIVAR_PATH" ]; then
        echo "PreviousBoot variable not found"
        return
    fi

    # Read the variable, skip first 4 bytes (attributes), convert from UTF-16
    local full_value=$(dd if="$EFIVAR_PATH" bs=1 skip=4 2>/dev/null | iconv -f UTF-16LE -t UTF-8 2>/dev/null | tr -d '\0')

    # Extract the useful substring that should be passed to set command
    if [[ "$full_value" == *"Microsoft"* ]]; then
        echo "Microsoft"
    elif [[ "$full_value" == *"EFI\\arch\\vmlinuz-linux"* ]]; then
        echo "EFI\\arch\\vmlinuz-linux"
    else
        # For unknown entries, return the full string
        echo "$full_value"
    fi
}

# Function to set next boot entry
set_next_boot() {
    local boot_entry="$1"

    # Add trailing space if not present
    if [[ ! "$boot_entry" =~ \ $ ]]; then
        boot_entry="$boot_entry "
    fi

    # Remove immutable flag if set
    chattr -i "$EFIVAR_PATH" 2>/dev/null || true

    # Create temporary file for the data
    local temp_file=$(mktemp)

    # Create the EFI variable data
    # 4 bytes attributes (0x00000007 = NV+BS+RT) + UTF-16 string + null terminator
    printf '\x07\x00\x00\x00' > "$temp_file"
    echo -n "$boot_entry" | iconv -f UTF-8 -t UTF-16LE >> "$temp_file"
    printf '\x00\x00' >> "$temp_file"

    # Copy to EFI variable
    cp "$temp_file" "$EFIVAR_PATH"

    # Clean up
    rm "$temp_file"

    echo "Successfully set rEFInd next boot to: ${boot_entry% }"
}

# Main script logic
case "${1:-}" in
    "get"|"")
        echo "Current PreviousBoot value:"
        get_current
        echo
        echo "Usage examples:"
        echo "  Boot to Windows:  sudo $0 \"Microsoft\""
        echo "  Boot to Arch:     sudo $0 \"EFI\\arch\\vmlinuz-linux\""
        ;;
    *)
        set_next_boot "$1"
        echo "You can now reboot to boot into the selected OS."
        echo "Run 'sudo reboot' when ready."
        ;;
esac
