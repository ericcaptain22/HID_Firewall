# File: scripts/device_detection.py

import platform
import subprocess
import os
import psutil

def detect_usb_devices():
    """
    Detect USB devices based on the operating system.
    """
    os_type = platform.system()
    devices = []

    try:
        if os_type == 'Linux':
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = result.stdout.split('\n')
            devices = [device for device in devices if device]

        elif os_type == 'Windows':
            # Use Windows command to list USB devices
            result = subprocess.run(
                ['wmic', 'path', 'Win32_PnPEntity', 'where', "DeviceID like '%USB%'", 'get', 'DeviceID,Name'],
                capture_output=True, text=True
            )
            devices = result.stdout.split('\n')
            devices = [device.strip() for device in devices if device.strip() and 'DeviceID' not in device]

        elif os_type == 'Darwin':  # macOS
            result = subprocess.run(['system_profiler', 'SPUSBDataType'], capture_output=True, text=True)
            devices = result.stdout.split('\n')
            devices = [device for device in devices if device]

        else:
            print(f"USB detection not implemented for {os_type}")
            return []

    except Exception as e:
        print(f"Error detecting USB devices: {e}")
        return []

    return devices


def get_storage_devices():
    """
    Retrieve mounted storage devices compatible with both Windows and Linux.
    """
    storage_devices = []

    os_type = platform.system()

    try:
        if os_type == 'Linux':
            result = subprocess.run(['lsblk', '-o',
'NAME,MOUNTPOINT'], capture_output=True, text=True)
            lines = result.stdout.splitlines()[1:]  # Skip header

            for line in lines:
                parts = line.split()
                if len(parts) == 2:
                    dev_name = parts[0]
                    mount_point = parts[1]
                    storage_devices.append((dev_name, mount_point))

        elif os_type == 'Windows':
            # Use WMIC command to get mounted volumes on Windows
            result = subprocess.run(['wmic', 'logicaldisk', 'get',
'DeviceID,VolumeName'], capture_output=True, text=True)
            lines = result.stdout.splitlines()[1:]  # Skip header

            for line in lines:
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 1:
                        dev_name = parts[0]
                        mount_point = dev_name  # On Windows, the DeviceID is the mount point
                        storage_devices.append((dev_name, mount_point))

        else:
            print(f"Storage retrieval not implemented for {os_type}")
            return []

    except Exception as e:
        print(f"Error retrieving storage devices: {e}")

    return storage_devices


def scan_usb_for_malicious_content(mount_point):
    """
    Scan USB devices for malicious content.
    """
    malicious_files = []
    try:
        for root, dirs, files in os.walk(mount_point):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()

                        # Check for malicious patterns (replace with actual patterns)
                        if "malicious" in content or ".ps1" in file or ".exe" in file:
                            malicious_files.append(file_path)

                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")

    except Exception as e:
        print(f"Error scanning USB content at {mount_point}: {e}")

    return malicious_files


def list_usb_devices(devices):
    """
    List details of detected USB devices and scan for malicious
content if possible.
    """
    storage_devices = get_storage_devices()  # Get mounted storage devices
    device_list = []

    for device in devices:
        device_info = device.strip().split(',')
        device_id = device_info[0].strip() if len(device_info) > 0 else "Unknown"
        device_name = device_info[1].strip() if len(device_info) > 1 else "Unknown"

        print(f"🛡️ Device ID: {device_id}, Name: {device_name}")

        # Match device with a mount point
        matched_mount_point = None
        for dev_name, mount_point in storage_devices:
            if device_id in dev_name:
                matched_mount_point = mount_point
                break

        if matched_mount_point:
            print(f"📍 Scanning device {device_id} at mount point {matched_mount_point}...")

            # Scan for malicious content
            malicious_files = scan_usb_for_malicious_content(matched_mount_point)

            if malicious_files:
                print(f"🚫 Malicious files detected on {device_id}:")
                for file in malicious_files:
                    print(f"  - {file}")
            else:
                print(f"✅ No malicious files detected on {device_id}.")

        else:
            print(f"⚠️ No mount point found for device {device_id}.")

        device_list.append(f"Device ID: {device_id}, Name: {device_name}")

    return device_list


if __name__ == "__main__":
    devices = detect_usb_devices()

    if devices:
        print("🔍 Detected USB Devices:")
        for device in list_usb_devices(devices):
            print(device)
    else:
        print("⚠️ No USB devices detected.")
