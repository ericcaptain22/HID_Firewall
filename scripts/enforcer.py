# File: scripts/enforcer.py

import ctypes
import time
import platform
import subprocess
import psutil
import threading
#import winreg
from ctypes import wintypes

# Import winreg only if on Windows
if platform.system() == "Windows":
    import winreg  # Windows-only module
else:
    winreg = None  # Assign None on Linux to avoid errors

# ===========================
# 🔥 Constants for API Hooking
# ===========================
WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_KEYUP = 0x0101
VK_LWIN = 0x5B  # Windows key
VK_R = 0x52     # R key
PROCESS_TERMINATE = 0x0001

key_hook_active = False


# ✅ Whitelisted processes (preserved)
WHITELIST_PROCESSES = {
    "python.exe", "svchost.exe", "taskmgr.exe", "explorer.exe", "powershell.exe"
}

# ===========================
# 🚫 Kernel-Level Key Hook (Instant Block)
# ===========================
def low_level_keyboard_proc(nCode, wParam, lParam):
    """Kernel hook to block Win + R instantly."""
    if nCode >= 0 and wParam in (WM_KEYDOWN, WM_KEYUP):
        vk_code = ctypes.cast(lParam, ctypes.POINTER(ctypes.c_ulong)).contents.value

        # 🚫 Instantly block Win + R combination
        if vk_code == VK_LWIN or vk_code == VK_R:
            print("🚫 Instantly blocking Win + R!")
            return 1  # Block the key event

    return ctypes.windll.user32.CallNextHookEx(None, nCode, wParam, lParam)


def block_win_r_combination():
    """Activate kernel-level key blocking."""
    global key_hook_active

    if platform.system() == "Windows" and not key_hook_active:
        print("🚫 Activating low-level key hook to block Win + R...")

        hook_proc = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p)(low_level_keyboard_proc)

        hook_id = ctypes.windll.user32.SetWindowsHookExA(
            WH_KEYBOARD_LL, hook_proc, ctypes.windll.kernel32.GetModuleHandleW(None), 0)

        if hook_id:
            key_hook_active = True
            print("✅ Kernel-level key hook activated successfully.")

            # Keep the hook running
            msg = ctypes.wintypes.MSG()
            while ctypes.windll.user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) != 0:
                ctypes.windll.user32.TranslateMessage(ctypes.byref(msg))
                ctypes.windll.user32.DispatchMessageW(ctypes.byref(msg))
        else:
            print("⚠️ Failed to activate key hook!")


# ===========================
# 🚫 Registry Protection
# ===========================
def disable_win_r_registry():
    """Block Win + R via Windows Registry."""
    if platform.system() == "Windows":
        try:
            print("🚫 Disabling Win + R via Registry...")

            with winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER) as reg:
                with winreg.CreateKey(reg, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer") as key:
                    winreg.SetValueEx(key, "NoRun", 0, winreg.REG_DWORD, 1)

            print("✅ Win + R disabled successfully.")
        except Exception as e:
            print(f"⚠️ Error disabling Win + R: {e}")


def enable_win_r_registry():
    """Restore Win + R via Registry."""
    if platform.system() == "Windows":
        try:
            print("🔓 Restoring Win + R via registry...")

            with winreg.ConnectRegistry(None, winreg.HKEY_CURRENT_USER) as reg:
                with winreg.OpenKey(reg, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", 0, winreg.KEY_ALL_ACCESS) as key:
                    winreg.DeleteValue(key, "NoRun")

            print("✅ Win + R restored.")
        except Exception as e:
            print(f"⚠️ Error restoring Win + R: {e}")


# ===========================
# 🚫 Real-Time Suspicious Process Killer
# ===========================
def terminate_suspicious_processes():
    """Instantly terminate suspicious processes while respecting the whitelist."""
    suspicious_processes = {
        "chrome.exe", "cmd.exe", "wscript.exe", "cscript.exe",
        "mshta.exe", "rundll32.exe", "regsvr32.exe", "schtasks.exe",
        "wmic.exe", "bitsadmin.exe", "msiexec.exe"
    }

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            process_name = proc.info['name'].lower()

            # Skip whitelisted processes
            if process_name in WHITELIST_PROCESSES:
                print(f"✅ Skipping whitelisted process: {process_name}")
                continue

            # 🚫 Instantly terminate suspicious processes
            if process_name in suspicious_processes:
                print(f"🚫 Instantly terminating: {process_name}")
                proc.terminate()

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


# ===========================
# 🔌 USB Watchdog (Instant Execution)
# ===========================
def disconnect_usb_devices():
    """Instantly disconnect USB devices when malicious activity is detected."""
    if platform.system() == "Windows":
        print("🔌 Disconnecting USB device...")
        try:
            disconnect_command = [
                'powershell',
                '-Command',
                (
                    "Get-PnpDevice -Class USB -Status OK | "
                    "Where-Object { $_.FriendlyName -match 'USB' } | "
                    "ForEach-Object { Disable-PnpDevice -InstanceId $_.InstanceId -Confirm:$false }"
                )
            ]

            result = subprocess.run(disconnect_command, check=True, capture_output=True, text=True)

            if result.returncode == 0:
                print("✅ USB device disconnected successfully.")
            else:
                print(f"⚠️ Failed to disconnect USB: {result.stderr}")

        except Exception as e:
            print(f"⚠️ Error disconnecting USB: {e}")


# ===========================
# 🚫 Enforce Security Actions (Instant)
# ===========================
def enforce_security(action, duration=None):
    """Enforce security measures instantly without looping."""
    try:
        if action == "block_input" and duration:
            print("🚫 Instantly blocking input...")
            ctypes.windll.user32.BlockInput(True)
            time.sleep(duration)
            ctypes.windll.user32.BlockInput(False)

        elif action == "terminate_processes":
            print("🚫 Instantly terminating suspicious processes...")
            terminate_suspicious_processes()

        elif action == "disable_win_r":
            print("🚫 Disabling Win + R...")
            disable_win_r_registry()

        elif action == "enable_win_r":
            print("🔓 Enabling Win + R...")
            enable_win_r_registry()

        elif action == "block_keystrokes":
            print("🚫 Activating real-time key blocking...")
            threading.Thread(target=block_win_r_combination, daemon=True).start()

        elif action == "usb_watchdog":
            print("🔌 Disconnecting USB devices instantly...")
            disconnect_usb_devices()

        elif action == "disconnect_usb_devices":
            print("🔌 Disconnecting USB devices instantly...")
            disconnect_usb_devices()

        else:
            print(f"⚠️ Invalid action: {action}")

    except Exception as e:
        print(f"❌ Error processing action '{action}': {e}")


# ===========================
# 🚫 Main Execution
# ===========================
if __name__ == "__main__":
    print("🚫 Enforcing security measures instantly...")

    # Block Win + R, Chrome, and USB instantly
    enforce_security("disable_win_r")
    enforce_security("block_keystrokes")
    enforce_security("terminate_processes")
    enforce_security("usb_watchdog")

    print("✅ Security measures active.")