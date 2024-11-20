import subprocess
import platform

def detect_usb_devices():
    os_type = platform.system()

    try:
        if os_type == 'Linux':
            # Linux: use lsusb to list USB devices
            result = subprocess.run(['lsusb'], capture_output=True, text=True)
            devices = result.stdout.split('\n')
            return [device for device in devices if device]
        elif os_type == 'Windows':
            # Windows: Use powershell command to list USB devices
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

def list_devices(devices):
    device_list = []
    for device in devices:
        # Format the device string as needed. This is just a basic example.
        device_list.append(device)
    return device_list

if __name__ == "__main__":
    devices = detect_usb_devices()
    if devices:
        print("Detected USB Devices:")
        for device in list_devices(devices):
            print(device)
    else:
        print("No USB devices detected.")
