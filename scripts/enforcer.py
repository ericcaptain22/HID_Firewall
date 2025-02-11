# File: scripts/enforcer.py

import ctypes
import time
import platform
import subprocess

def block_input(duration):
    """
    Block all user input for a specified duration.
    Currently implemented for Windows. On Linux and macOS, it logs a message.
    """
    os_type = platform.system()
    if os_type == "Windows":
        ctypes.windll.user32.BlockInput(True)
        time.sleep(duration)
        ctypes.windll.user32.BlockInput(False)
    elif os_type == "Linux":
        print(f"Blocking input is not directly supported on Linux. Simulating blocking for {duration} seconds.")
        time.sleep(duration)  # Simulate blocking
    elif os_type == "Darwin":  # macOS
        print(f"Blocking input is not directly supported on macOS. Simulating blocking for {duration} seconds.")
        time.sleep(duration)  # Simulate blocking
    else:
        raise NotImplementedError(f"Input blocking is not implemented for {os_type}")

def disconnect_device(device):
    """
    Disconnect a specified USB device.
    Currently implemented as a placeholder.
    """
    print(f"Simulating disconnection of device: {device}")
    # Add actual disconnection logic if feasible for your platform.

def lock_system():
    """
    Lock the operating system.
    """
    os_type = platform.system()
    if os_type == "Windows":
        ctypes.windll.user32.LockWorkStation()
    elif os_type == "Linux":
        try:
            subprocess.call(["gnome-screensaver-command", "--lock"])
        except FileNotFoundError:
            print("Gnome screensaver not available. Unable to lock the system.")
    elif os_type == "Darwin":  # macOS
        subprocess.call(['/System/Library/CoreServices/Menu Extras/User.menu/Contents/Resources/CGSession', '-suspend'])
    else:
        raise NotImplementedError(f"System locking is not implemented for {os_type}")

def enforce_security(action, duration=None, device=None):
    """
    Enforce security measures based on the specified action.
    """
    try:
        if action == "block_input" and duration:
            block_input(duration)
        elif action == "disconnect_device" and device:
            disconnect_device(device)
        elif action == "lock_system":
            lock_system()
        else:
            raise ValueError("Invalid action or missing parameters")
    except Exception as e:
        print(f"Failed to enforce security action '{action}': {e}")

if __name__ == "__main__":
    # Example usage
    enforce_security("block_input", duration=5)
    # enforce_security("disconnect_device", device="USB_Device_Name")
    # enforce_security("lock_system")
