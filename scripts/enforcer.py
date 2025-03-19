# File: scripts/enforcer.py

import ctypes
import time
import platform
import subprocess
import psutil

def block_input(duration):
    """
    Block all user input for a specified duration.
    """
    os_type = platform.system()

    if os_type == "Windows":
        ctypes.windll.user32.BlockInput(True)
        time.sleep(duration)
        ctypes.windll.user32.BlockInput(False)

    elif os_type == "Linux":
        try:
            result = subprocess.run(['xinput', 'list'],
capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "keyboard" in line.lower():
                    device_id = line.split()[5].split('=')[1]
                    subprocess.run(['xinput', 'disable', device_id])
                    time.sleep(duration)
                    subprocess.run(['xinput', 'enable', device_id])
        except Exception as e:
            print(f"⚠️ Error blocking input on Linux: {e}")
    else:
        print(f"⚠️ Input blocking not supported on {os_type}")


def lock_system():
    """
    Lock the operating system.
    """
    os_type = platform.system()

    if os_type == "Windows":
        ctypes.windll.user32.LockWorkStation()

    elif os_type == "Linux":
        subprocess.call(["gnome-screensaver-command", "--lock"])

    elif os_type == "Darwin":  # macOS
        subprocess.call(['/System/Library/CoreServices/MenuExtras/User.menu/Contents/Resources/CGSession', '-suspend'])

    else:
        print(f"⚠️ System locking not supported on {os_type}")


def terminate_suspicious_processes():
    """
    Terminate suspicious processes.
    """
    suspicious_processes = {
        "cmd.exe", "wscript.exe", "cscript.exe", "explorer.exe", "chrome.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "schtasks.exe",
        "wmic.exe", "bitsadmin.exe", "msiexec.exe"
    }

    whitelist = {
        "firefox.exe", "taskmgr.exe",
        "python.exe", "svchost.exe", "dllhost.exe", "powershell.exe"
    }

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            process_name = proc.info['name'].lower()

            if process_name.endswith('.exe'):
                if process_name in whitelist:
                    print(f"✅ Skipping whitelisted process: {process_name}")
                    continue

                if process_name in suspicious_processes:
                    print(f"🚫 Terminating suspicious process: {process_name}")
                    proc.terminate()

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def disconnect_device():
    """
    Disconnect USB device (Windows only) using PowerShell.
    """
    os_type = platform.system()

    if os_type == "Windows":
        print("🔌 Disconnecting USB device...")
        try:
            # Use Get-PnpDevice to list and disable USB devices
            disconnect_command = [
                'powershell',
                '-Command',
                (
                    "Get-PnpDevice -Class USB -Status OK | "
                    "Where-Object { $_.FriendlyName -match 'USB' } | "
                    "ForEach-Object { Disable-PnpDevice -InstanceId$_.InstanceId -Confirm:$false }"
                )
            ]

            result = subprocess.run(disconnect_command, check=True,
capture_output=True, text=True)

            if result.returncode == 0:
                print("✅ USB device disconnected successfully.")
            else:
                print(f"⚠️ Failed to disconnect USB device: {result.stderr}")

        except Exception as e:
            print(f"⚠️ Error disconnecting USB: {e}")

    else:
        print(f"⚠️ USB disconnection is not supported on {os_type}")



def enforce_security(action, duration=None):
    """
    Enforce security measures based on the specified action.
    Actions: "block_input", "terminate_processes", "lock_system",
"disconnect_device".
    """
    try:
        if action == "block_input" and duration:
            print("🚫 Blocking input...")
            block_input(duration)

        elif action == "terminate_processes":
            print("🚫 Terminating suspicious processes...")
            terminate_suspicious_processes()

        elif action == "lock_system":
            print("🔒 Locking system...")
            lock_system()

        elif action == "disconnect_device":
            print("🔌 Disconnecting USB device...")
            disconnect_device()

        else:
            raise ValueError(f"Invalid action or missing parameters: {action}")

    except Exception as e:
        print(f"❌ Error processing action '{action}': {e}")


if __name__ == "__main__":
    # Test blocking input for 5 seconds
    print("🚫 Blocking input for 5 seconds...")
    enforce_security("block_input", duration=5)

    # Terminate suspicious processes
    print("🚫 Terminating suspicious processes...")
    enforce_security("terminate_processes")

    # Lock system
    print("🔒 Locking system...")
    enforce_security("lock_system")

    # Disconnect USB device (Windows only)
    print("🔌 Disconnecting USB device...")
    enforce_security("disconnect_device")