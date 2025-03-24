# File: scripts/device_detection.py

import platform
import subprocess
import os

# ================================
# 🚀 Detect USB Devices
# ================================
def detect_usb_devices():
    """Detect USB devices on Windows and Linux."""
    devices = []

    try:
        if platform.system() == 'Windows':
            print("🔍 Detecting USB devices on Windows...")

            # Use PowerShell to fetch detailed USB information
            result = subprocess.run(
                [
                    'powershell',
                    '-Command',
                    """
                    Get-WmiObject Win32_PnPEntity |
                    Where-Object { $_.DeviceID -match 'USB' } |
                    Select-Object DeviceID, Caption
                    """
                ],
                capture_output=True, text=True
            )

            if result.returncode == 0:
                lines = result.stdout.splitlines()

                # Skip header lines
                for line in lines[3:]:
                    line = line.strip()
                    if line:
                        devices.append(line)

        elif platform.system() == 'Linux':
            print("🔍 Detecting USB devices on Linux...")

            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            if result.returncode == 0:
                devices = result.stdout.splitlines()

        else:
            print("⚠️ Unsupported OS for USB detection.")
    except Exception as e:
        print(f"❌ Error detecting USB devices: {e}")

    return devices

# ================================
# 🔎 Extract VID, PID, and Friendly Name
# ================================
def parse_usb_output(device):
    """
    Extract VID, PID, and Friendly Name from the device output.
    """
    vid, pid, friendly_name = "Unknown", "Unknown", "Unknown"

    if platform.system() == "Windows":
        try:
            parts = device.split()
            for part in parts:
                if "VID_" in part and "&PID_" in part:
                    vid = part.split("VID_")[1].split("&")[0]
                    pid = part.split("PID_")[1].split("&")[0]
                elif part not in ("DeviceID", "Caption") and len(part) > 4:
                    friendly_name = " ".join(parts[2:])

        except Exception as e:
            print(f"⚠️ Error parsing USB details: {e}")

    elif platform.system() == "Linux":
        try:
            parts = device.split()
            vid, pid = parts[5].split(":")
            friendly_name = " ".join(parts[6:])
        except Exception as e:
            print(f"⚠️ Error parsing Linux USB details: {e}")

    return vid, pid, friendly_name


# ================================
# 🔥 List USB Devices
# ================================
def list_usb_devices(devices):
    """List and display USB devices with clean output."""
    device_list = []

    for device in devices:
        vid, pid, name = parse_usb_output(device)

        if vid != "Unknown" and pid != "Unknown":
            device_info = f"🛡️ VID: {vid} | PID: {pid} → {name}"
        else:
            device_info = f"⚠️ Unknown Device → {device}"

        print(device_info)  # Display in terminal
        device_list.append(device_info)

    return device_list


# ================================
# 🔥 MAIN EXECUTION
# ================================
if __name__ == "__main__":
    devices = detect_usb_devices()

    if devices:
        print("\n🛡️ Detected USB Devices:\n")
        for device in list_usb_devices(devices):
            print(device)
    else:
        print("⚠️ No USB devices detected.")