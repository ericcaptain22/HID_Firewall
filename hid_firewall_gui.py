import tkinter as tk
from tkinter import scrolledtext, Toplevel, Label, Button
import threading
from pynput import keyboard
import re
from scripts import sandbox_analysis
from scripts import enforcer
from scripts import device_detection
from scripts import keystroke_interception
from scripts.encryption import encrypt_data, decrypt_data  # Import encryption functions
from scripts.malicious_input_engine import analyze_keystroke, load_trained_model

# Malicious patterns
MALICIOUS_PATTERNS = [
    re.compile(r'echo\s+bad', re.IGNORECASE),
]

def is_malicious(keystroke):
    for pattern in MALICIOUS_PATTERNS:
        if pattern.search(keystroke):
            return True
    return False

def analyze_keystroke(keystroke):
    if is_malicious(keystroke):
        print(f'Malicious keystroke detected: {keystroke}')
        analysis_result = sandbox_analysis.analyze_keystroke_sandbox(keystroke)
        print(analysis_result)
        return True
    return False

class HIDFirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HID Firewall")
        self.root.geometry("800x700")
        self.root.configure(bg="#282c34")

        self.style = {
            "font": ("Helvetica", 12),
            "bg": "#282c34",
            "fg": "#61dafb",
            "highlight_bg": "#20232a",
            "button_bg": "#61dafb",
            "button_fg": "#20232a"
        }
        
        #Load trained model
        self.vectorizer, self.clf = load_trained_model()
      
        # USB Devices Frame
        self.usb_frame = tk.LabelFrame(self.root, text="Detected USB Devices", 
                                       font=self.style["font"], bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.usb_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.usb_list = scrolledtext.ScrolledText(self.usb_frame, height=12, font=self.style["font"], bg="white", fg="black", state='disabled')
        self.usb_list.pack(fill="both", expand="yes", padx=10, pady=10)

        self.refresh_button = tk.Button(self.usb_frame, text="Refresh Devices", command=self.list_usb_devices,
                                        font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.refresh_button.pack(pady=5)

        # Keystrokes Frame
        self.keystroke_frame = tk.LabelFrame(self.root, text="Intercepted Keystrokes", 
                                             font=self.style["font"], bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.keystroke_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.keystroke_list = scrolledtext.ScrolledText(self.keystroke_frame, height=12, font=self.style["font"], bg="white", fg="black")
        self.keystroke_list.pack(fill="both", expand="yes", padx=10, pady=10)

        self.keystroke_list.tag_configure("highlight", foreground="#ff9900", font=("Helvetica", 20, "bold"))

        # Control Buttons
        self.control_frame = tk.Frame(self.root, bg=self.style["bg"])
        self.control_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.start_button = tk.Button(self.control_frame, text="Start HID Firewall", command=self.start_firewall,
                                      font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.start_button.pack(side="left", padx=10)

        self.stop_button = tk.Button(self.control_frame, text="Stop HID Firewall", command=self.stop_firewall, state=tk.DISABLED,
                                     font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.stop_button.pack(side="left", padx=10)

        self.running = False
        self.listener = None

    def list_usb_devices(self):
        devices = device_detection.detect_usb_devices()
        self.device_analysis_results = []  # Store analysis results
        device_list = device_detection.list_devices(devices)
        self.usb_list.config(state='normal')
        self.usb_list.delete('1.0', tk.END)
        for device in device_list:
            self.usb_list.insert(tk.END, f"Device: {device}\n")
            # Read the contents of the USB device (this is a placeholder, implement your own method)
            content = self.read_usb_contents(device)
            self.usb_list.insert(tk.END, f"Contents:\n{content}\n")
            analysis_result = sandbox_analysis.analyze_usb_device_sandbox(device)
            self.device_analysis_results.append((device, analysis_result))
            print(analysis_result)
        self.usb_list.config(state='disabled')

    def read_usb_contents(self, device):
        # Implement your own method to read contents from the USB device
        # This is a placeholder implementation
        return "Sample content of the USB device.\n"

    def on_press(self, key):
        try:
            keystroke = f'{key.char}'
        except AttributeError:
            keystroke = f'{key}'
        
        encrypted_keystroke = encrypt_data(keystroke)
        decrypted_keystroke = decrypt_data(encrypted_keystroke)
        
        self.keystroke_list.insert(tk.END, f'\nEncrypted: {encrypted_keystroke}\nDecrypted: {decrypted_keystroke}\n')

        if analyze_keystroke(decrypted_keystroke):
            self.keystroke_list.insert(tk.END, 'Blocking input for 5 seconds...\n', 'highlight')
            enforcer.enforce_security("block_input", duration=5)  # Use the enforcer to block input
            enforcer.enforce_security("lock_system")
            # enforcer.enforce_security("disconnect_device", device="Device Name")

    def on_release(self, key):
        if key == keyboard.Key.esc:
            return False

    def start_firewall(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.listener = keyboard.Listener(on_press=self.on_press, on_release=self.on_release)
        self.listener.start()
        self.keystroke_list.insert(tk.END, 'HID Firewall started...\n', 'highlight')

        # Start keystroke listener in a separate thread
        self.listener_thread = threading.Thread(target=keystroke_interception.start_listener)
        self.listener_thread.start()

    def stop_firewall(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        if self.listener:
            self.listener.stop()
            self.listener = None
        self.keystroke_list.insert(tk.END, 'HID Firewall stopped...\n', 'highlight')
        
        # Determine if any USB device is malicious
        malicious_detected = any(result for device, result in self.device_analysis_results if result == "malicious")
        if malicious_detected:
            self.show_custom_alert("USB Device Alert", "Warning! A malicious USB device has been detected. Immediate action is required to secure your system.", "warning")
        else:
            self.show_custom_alert("USB Device Alert", "All connected USB devices are safe. No malicious activity detected. Your system is secure.", "info")

    def show_custom_alert(self, title, message, alert_type):
        alert = Toplevel(self.root)
        alert.title(title)
        alert.geometry("400x200")
        alert.configure(bg=self.style["bg"])

        msg_label = Label(alert, text=message, font=("Helvetica", 18, "bold"), bg=self.style["bg"], fg=self.style["fg"], wraplength=330)
        msg_label.pack(pady=20)

        if alert_type == "warning":
            msg_label.configure(fg="red")

        ok_button = Button(alert, text="OK", command=alert.destroy, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        ok_button.pack(pady=10)
    



if __name__ == "__main__":
    root = tk.Tk()
    app = HIDFirewallApp(root)
    root.mainloop()
