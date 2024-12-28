import tkinter as tk
from tkinter import scrolledtext, Toplevel, Label, Button
import threading
from pynput import keyboard
import re
from tkinter import messagebox, scrolledtext, filedialog
import pickle
import threading
from scripts import sandbox_analysis
from scripts import enforcer
from scripts import device_detection
from scripts import keystroke_interception
from scripts.encryption import encrypt_message, decrypt_message  # Import encryption functions
#from tensorflow.keras.models import load_model
from tensorflow.keras.models import load_model
from models.train_payload_model import pad_sequences, read_file_content
from scripts.malicious_input_engine import load_payload_model_rf, analyze_keystroke_partial
from scripts.malicious_input_engine import analyze_keystroke, load_keystroke_model, analyze_keystroke, load_payload_model_lstm, preprocess_content
from scripts.keystroke_interception import preprocess_command, keystroke_vectorizer, keystroke_clf, analyze_command_ngrams
from scripts.sandbox_analysis import analyze_keystroke_sandbox, analyze_usb_device_sandbox
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
    processed_keystroke = preprocess_command(keystroke)
    if analyze_keystroke(processed_keystroke, keystroke_vectorizer, keystroke_clf):
        print(f"Malicious command detected: {processed_keystroke}")
        return True
    return False

def analyze_keystroke(keystroke):
    """Analyze a command to check if it is malicious."""
    processed_keystroke = preprocess_command(keystroke)  # Ensure proper preprocessing
    print(f"Processed Command: {processed_keystroke}")   # Debug the preprocessed command

    # Perform the analysis
    if analyze_keystroke(processed_keystroke, keystroke_vectorizer, keystroke_clf):
        print(f"Malicious command detected: {processed_keystroke}")
        return True
    else:
        print(f"Command is benign: {processed_keystroke}")
        return False

def analyze_payload_lstm(filepath, lstm_model, tokenizer):
    """Analyze a file's content using the LSTM model."""
    try:
        content = read_file_content(filepath)
        processed_content = preprocess_content(content)
        sequence = tokenizer.texts_to_sequences([processed_content])
        padded_sequence = pad_sequences(sequence, maxlen=100, padding='post', truncating='post')
        prediction = lstm_model.predict(padded_sequence)
        return prediction[0][0] > 0.5  # Threshold for malicious detection
    except Exception as e:
        print(f"Error analyzing file with LSTM: {e}")
        return False

def analyze_payload_rf(filepath, vectorizer, clf):
    """Analyze a file's content using the Random Forest model."""
    try:
        content = read_file_content(filepath)
        processed_content = preprocess_content(content)
        X_test = vectorizer.transform([processed_content])
        prediction = clf.predict(X_test)
        return prediction[0] == 1
    except Exception as e:
        print(f"Error analyzing file with Random Forest: {e}")
        return False


def analyze_keystroke(keystroke):
    if is_malicious(keystroke):
        print(f'Malicious keystroke detected: {keystroke}')
        analysis_result = sandbox_analysis.analyze_keystroke_sandbox(keystroke)
        print(analysis_result)
        return True
    return False

def analyze_file_with_lstm(self, filepath):
    """Analyze a file's content using the LSTM model."""
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            content = file.read()
        processed_content = preprocess_content(content)
        sequence = self.lstm_tokenizer.texts_to_sequences([processed_content])
        padded_sequence = pad_sequences(sequence, maxlen=100, padding='post', truncating='post')
        prediction = self.lstm_model.predict(padded_sequence)
        return prediction[0][0] > 0.5  # Threshold of 0.5 for malicious detection
    except Exception as e:
        print(f"Error analyzing file with LSTM: {e}")
        return False

def analyze_file_with_rf(self, filepath):
    """Analyze a file's content using the Random Forest model."""
    try:
        with open(filepath, "r", encoding="utf-8") as file:
            content = file.read()
        processed_content = preprocess_content(content)
        X_test = self.rf_vectorizer.transform([processed_content])
        prediction = self.rf_clf.predict(X_test)
        return prediction[0] == 1  # Label 1 indicates malicious
    except Exception as e:
        print(f"Error analyzing file with Random Forest: {e}")
        return False



class HIDFirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HID Firewall")
        self.root.geometry("1000x1200")
        self.root.configure(bg="#282c34")

        self.style = {
            "font": ("Helvetica", 12),
            "bg": "#282c34",
            "fg": "#61dafb",
            "highlight_bg": "#20232a",
            "button_bg": "#61dafb",
            "button_fg": "#20232a"
        }
        
        #Load trained models
        self.keystroke_vectorizer, self.keystroke_clf = load_keystroke_model()
        self.payload_vectorizer, self.payload_clf = load_payload_model_lstm()
        # Inside the __init__ method of HIDFirewallApp
        self.rf_vectorizer, self.rf_clf = load_payload_model_rf()  # Load Random Forest model
        self.lstm_model = load_model('models/lstm_payload_model.h5')  # Load LSTM model
        with open('models/tokenizer.pkl', 'rb') as tokenizer_file:
            self.lstm_tokenizer = pickle.load(tokenizer_file)   

        
        # Manual Input Frame
        self.input_frame = tk.LabelFrame(self.root, text="Manual Command Input", 
                                         font=self.style["font"], bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.input_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.input_textarea = scrolledtext.ScrolledText(self.input_frame, height=6, font=self.style["font"], bg="white", fg="black")
        self.input_textarea.pack(fill="both", expand="yes", padx=10, pady=10)

        self.analyze_button = tk.Button(self.input_frame, text="Analyze Input", command=self.analyze_manual_input,
                                        font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.analyze_button.pack(pady=5)

        # File Upload Frame
        self.file_frame = tk.LabelFrame(self.root, text="Upload Log File for Analysis", 
                                        font=self.style["font"], bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.file_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.upload_button = tk.Button(self.file_frame, text="Upload File", command=self.upload_file,
                                       font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.upload_button.pack(pady=5)

        self.file_results = scrolledtext.ScrolledText(self.file_frame, height=5, font=self.style["font"], bg="white", fg="black", state='disabled')
        self.file_results.pack(fill="both", expand="yes", padx=10, pady=10)



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

        self.keystroke_list = scrolledtext.ScrolledText(self.keystroke_frame, height=7, font=self.style["font"], bg="white", fg="black")
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
        device_list = device_detection.list_usb_devices(devices)
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
        sandbox_result = analyze_usb_device_sandbox(content)
        if sandbox_result['status'] == 'malicious':
            self.usb_list.insert(tk.END, f"Sandbox Alert: {sandbox_result['details']}\n", "highlight")

    def analyze_manual_input(self):
        """Analyze commands typed manually in the textarea."""
        input_text = self.input_textarea.get("1.0", tk.END).strip()
        if not input_text:
            self.show_custom_alert("Input Error", "Please enter a command or text for analysis.")
            return
        
        # Encrypt and analyze each line
        results = []
        for line in input_text.splitlines():
            encrypted = encrypt_message(line)
            decrypted = decrypt_message(encrypted)
            if analyze_command_ngrams(decrypted):
                results.append(f"Malicious: {line}")
            else:
                results.append(f"Benign: {line}")
        
        self.show_custom_alert("Analysis Results", "\n".join(results), "warning")

    def upload_file(self):
        """Upload a .txt file and analyze its contents."""
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if not file_path:
            return

        try:
            with open(file_path, 'r') as file:
                lines = file.readlines()
            
            self.file_results.config(state='normal')
            self.file_results.delete("1.0", tk.END)

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if analyze_command_ngrams(line):
                    self.file_results.insert(tk.END, f"Malicious: {line}\n", "highlight")
                else:
                    self.file_results.insert(tk.END, f"Benign: {line}\n")
            
            self.file_results.config(state='disabled')
        except Exception as e:
            messagebox.showerror("File Error", f"Error reading the file: {e}")

    def read_usb_contents(self, device):
        # Implement your own method to read contents from the USB device
        # This is a placeholder implementation from USB
        return "Sample content of the USB device.\n"
        
    def on_press(self, key):
        """Handle intercepted keystrokes."""
        try:
            keystroke = key.char if hasattr(key, 'char') else str(key)
            encrypted_keystroke = encrypt_message(keystroke)
            decrypted_keystroke = decrypt_message(encrypted_keystroke)

            self.keystroke_list.insert(tk.END, f'\nEncrypted: {encrypted_keystroke}\nDecrypted: {decrypted_keystroke}\n')
            
            if analyze_keystroke_sandbox(keystroke)['status'] == 'malicious':
                print(f"Malicious keystroke detected: {keystroke}")
                self.keystroke_list.insert(tk.END, "Sandbox Alert: Malicious keystroke detected.\n", "highlight")

            if analyze_keystroke(keystroke, self.keystroke_vectorizer, self.keystroke_clf):
                self.keystroke_list.insert(tk.END, f'Malicious detected: {keystroke}\n', 'highlight')
                enforcer.enforce_security("block_input", duration=5)

            if analyze_keystroke_partial(keystroke, self.keystroke_vectorizer, self.keystroke_clf):
                self.keystroke_list.insert(tk.END, f'Malicious detected: {keystroke}\n', 'highlight')
                enforcer.enforce_security("block_input", duration=5)

            if analyze_keystroke(decrypted_keystroke, self.keystroke_vectorizer, self.keystroke_clf):
                self.keystroke_list.insert(tk.END, 'Blocking input for 5 seconds...\n', 'highlight')
                enforcer.enforce_security("block_input", duration=5)  # Use enforcer to block input
        except Exception as e:
            self.keystroke_list.insert(tk.END, f"Error: {e}\n")

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