import subprocess
import platform
import os

def detect_usb_devices():
    """
    Detect USB devices based on the operating system.
    """
    os_type = platform.system()

    try:
        if os_type == 'Linux':
            # Linux: use lsusb to list USB devices
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = result.stdout.split('\n')
            return [device for device in devices if device]
        elif os_type == 'Windows':
            # Windows: Use PowerShell command to list USB devices
            result = subprocess.run(['powershell', 'Get-PnpDevice -Class USB'], capture_output=True, text=True, shell=True)
            devices = result.stdout.split('\n')
            return [device for device in devices if device]
        elif os_type == 'Darwin':  # macOS
            # macOS: Use system_profiler command to list USB devices
            result = subprocess.run(['system_profiler', 'SPUSBDataType'], capture_output=True, text=True)
            devices = result.stdout.split('\n')
            return [device for device in devices if device]
        else:
            print(f"USB detection not implemented for {os_type}")
            return []
    except Exception as e:
        print(f"Error detecting USB devices: {e}")
        return []

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
    device_list = []
    for device in devices:
        # Example: Linux-specific device parsing for demonstration purposes
        if "ID" in device:
            details = device.split()
            device_id = details[5] if len(details) > 5 else "Unknown"
            device_list.append(f"Device ID: {device_id}, Details: {device}")
            print(f"Scanning device {device_id} for malicious content...")

            # Example mount point for USB devices in Linux (adjust as needed)
            mount_point = f"/media/{os.getlogin()}/{device_id}"
            if os.path.exists(mount_point):
                malicious_files = scan_usb_for_malicious_content(mount_point)
                if malicious_files:
                    print(f"Malicious files detected on device {device_id}:")
                    for file in malicious_files:
                        print(f"  - {file}")
                else:
                    print(f"No malicious files detected on device {device_id}.")
            else:
                print(f"Mount point {mount_point} does not exist for device {device_id}.")
    return device_list

if __name__ == "__main__":
    devices = detect_usb_devices()
    if devices:
        print("Detected USB Devices:")
        for device in list_usb_devices(devices):
            print(device)
    else:
        print("No USB devices detected.")
