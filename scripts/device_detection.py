import subprocess
import platform
import os
import re

def detect_usb_devices():
    """
    Detect USB devices based on the operating system.
    """
    
    os_type = platform.system()
    try:
        if os_type == 'Linux':
            # Linux: use lsusb to list USB devices
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = result.stdout.strip().split('\n')
            return [device for device in devices if device]
        elif os_type == 'Windows':
            # Windows: Use PowerShell command to list USB devices
            result = subprocess.run(['powershell', 'Get-PnpDevice -Class USB'], capture_output=True, text=True, shell=True)
            devices = result.stdout.strip().split('\n')
            return [device for device in devices if device]
        elif os_type == 'Darwin':  # macOS
            # macOS: Use system_profiler command to list USB devices
            result = subprocess.run(['system_profiler', 'SPUSBDataType'], capture_output=True, text=True)
            devices = result.stdout.strip().split('\n')
            return [device for device in devices if device]
        else:
            print(f"USB detection not implemented for {os_type}")
            return []
    except Exception as e:
        print(f"Error detecting USB devices: {e}")
        return []

def get_storage_devices():
    """
    Retrieve the list of mounted USB storage devices.
    """
    storage_devices = []
    try:
        result = subprocess.run(['lsblk', '-o', 'NAME,MOUNTPOINT,VENDOR,MODEL'], capture_output=True, text=True)
        lines = result.stdout.strip().split('\n')[1:]  # Skip the header line
        for line in lines:
            parts = re.split(r'\s{2,}', line)  # Split by two or more spaces
            if len(parts) >= 2 and parts[1]:  # Ensure there's a mount point
                storage_devices.append((parts[0], parts[1]))  # (Device name, Mount point)
    except Exception as e:
        print(f"Error retrieving storage devices: {e}")
    return storage_devices

def scan_usb_for_malicious_content(mount_point):
    """
    Scan USB devices for malicious content by searching for specific keywords in files.
    """
    malicious_files = []
    try:
        for root, dirs, files in os.walk(mount_point):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        if "malicious_keyword" in content:  # Replace with actual keywords or patterns
                            malicious_files.append(file_path)
                except Exception as e:
                    print(f"Error reading file {file_path}: {e}")
    except Exception as e:
        print(f"Error scanning USB content at {mount_point}: {e}")
    return malicious_files

def list_usb_devices(devices):
    """
    List details of detected USB devices and scan for malicious content if possible.
    """
    storage_devices = get_storage_devices()  # Get mounted storage devices
    device_list = []  # Store device details for GUI display

    for device in devices:
        if "ID" in device:
            details = device.split()
            device_id = details[5] if len(details) > 5 else "Unknown"
            device_entry = {"device_id": device_id, "details": device, "status": "Unknown"}

            # Match device with a mount point
            matched_mount_point = None
            for dev_name, mount_point in storage_devices:
                if device_id.split(":")[0] in dev_name:  # Match by vendor ID
                    matched_mount_point = mount_point
                    break

            if matched_mount_point:
                device_entry["status"] = f"Mounted at {matched_mount_point}"
                device_entry["mount_point"] = matched_mount_point

                # Scan for malicious content
                malicious_files = scan_usb_for_malicious_content(matched_mount_point)
                if malicious_files:
                    device_entry["malicious_files"] = malicious_files
                    device_entry["malicious_status"] = "Malicious files detected"
                else:
                    device_entry["malicious_files"] = []
                    device_entry["malicious_status"] = "No malicious files detected"
            else:
                device_entry["status"] = "No mount point found"

            device_list.append(device_entry)

    return device_list


if __name__ == "__main__":
    devices = detect_usb_devices()
    if devices:
        print("Detected USB Devices:")
        for device_info in list_usb_devices(devices):
            print(f"Device ID: {device_info['device_id']}")
            print(f"Details: {device_info['details']}")
            print(f"Status: {device_info['status']}")
            if "mount_point" in device_info:
                print(f"Mount Point: {device_info['mount_point']}")
                print(f"Malicious Status: {device_info['malicious_status']}")
                for malicious_file in device_info["malicious_files"]:
                    print(f"  - {malicious_file}")
            print()
    else:
        print("No USB devices detected.")

