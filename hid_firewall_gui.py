import tkinter as tk
from tkinter import scrolledtext, Toplevel, Label, Button
import threading
from pynput import keyboard
import re
from tkinter import messagebox, scrolledtext, filedialog
from tkinter.filedialog import askopenfilename
import pickle
import threading
from scripts import sandbox_analysis
from scripts import enforcer
from scripts.enforcer import enforce_security
from scripts import device_detection
from scripts import keystroke_interception
from scripts.keystroke_interception import analyze_keystroke as intercept_keystroke
from scripts.encryption import encrypt_message, decrypt_message  #Import encryption functions
#from tensorflow.keras.models import load_model
from tensorflow.keras.models import load_model
from models.train_payload_model import pad_sequences, read_file_content
from scripts.malicious_input_engine import load_payload_model_rf, analyze_keystroke_partial, load_kaggle_model, analyze_kaggle_payload
from scripts.malicious_input_engine import analyze_keystroke, load_keystroke_model, analyze_keystroke, load_payload_model_lstm, preprocess_content
from scripts.keystroke_interception import preprocess_command, keystroke_vectorizer, keystroke_clf, analyze_command_ngrams
from scripts.sandbox_analysis import analyze_keystroke_sandbox, analyze_usb_device_sandbox
from models.train_kaggle_model import load_and_preprocess_kaggle_dataset

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
    if analyze_keystroke(processed_keystroke, keystroke_vectorizer,
keystroke_clf):
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
    """
    Analyze a keystroke for malicious patterns using the keystroke model.
    """
# Load the keystroke model
    vectorizer, clf = load_keystroke_model()

    # Perform analysis
    if analyze_keystroke(keystroke):  # Pass all 3 required arguments
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
        padded_sequence = pad_sequences(sequence, maxlen=100,
padding='post', truncating='post')
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


        self.malicious_keystroke_detected = False  # Track keystroke detection

        #Load trained models
        self.keystroke_vectorizer, self.keystroke_clf = load_keystroke_model()
        self.payload_vectorizer, self.payload_clf = load_payload_model_lstm()
        # Inside the __init__ method of HIDFirewallApp
        self.rf_vectorizer, self.rf_clf = load_payload_model_rf()  #Load Random Forest model
        self.lstm_model = load_model('models/lstm_payload_model.h5')# Load LSTM model
        with open('models/tokenizer.pkl', 'rb') as tokenizer_file:
            self.lstm_tokenizer = pickle.load(tokenizer_file)


        # Manual Input Frame
        self.input_frame = tk.LabelFrame(self.root, text="Manual Command Input", font=self.style["font"],
        bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.input_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.input_textarea = scrolledtext.ScrolledText(self.input_frame, height=6, font=self.style["font"], bg="white", fg="black")
        self.input_textarea.pack(fill="both", expand="yes", padx=10, pady=10)

        self.analyze_button = tk.Button(self.input_frame, text="Analyze Input", command=self.analyze_manual_input, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.analyze_button.pack(pady=5)

        # File Upload Frame
        self.file_frame = tk.LabelFrame(self.root, text="Upload Log File for Analysis", font=self.style["font"],bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.file_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.upload_button = tk.Button(self.file_frame, text="Upload File", command=self.upload_file, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.upload_button.pack(pady=5)

        self.file_results = scrolledtext.ScrolledText(self.file_frame, height=5, font=self.style["font"], bg="white", fg="black", state='disabled')
        self.file_results.pack(fill="both", expand="yes", padx=10, pady=10)

        # Ensure control_frame is initialized early
        self.control_frame = tk.Frame(self.root, bg=self.style["bg"])
        self.control_frame.pack(fill="both", expand="yes", padx=10, pady=10)


        # USB Devices Frame
        self.usb_frame = tk.LabelFrame(self.root, text="Detected USB Devices", font=self.style["font"],bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.usb_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.usb_list = scrolledtext.ScrolledText(self.usb_frame, height=12, font=self.style["font"], bg="white", fg="black", state='disabled')
        self.usb_list.pack(fill="both", expand="yes", padx=10, pady=10)

        self.refresh_button = tk.Button(self.usb_frame, text="Refresh Devices", command=self.list_usb_devices, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.refresh_button.pack(pady=5)

        # Keystrokes Frame
        self.keystroke_frame = tk.LabelFrame(self.root,text="Intercepted Keystrokes", font=self.style["font"], bg=self.style["highlight_bg"], fg=self.style["fg"])
        self.keystroke_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.keystroke_list = scrolledtext.ScrolledText(self.keystroke_frame, height=7, font=self.style["font"], bg="white", fg="black")
        self.keystroke_list.pack(fill="both", expand="yes", padx=10, pady=10)

        self.keystroke_list.tag_configure("highlight", foreground="#ff9900", font=("Helvetica", 20, "bold"))

        # Control Buttons
        self.control_frame = tk.Frame(self.root, bg=self.style["bg"])
        self.control_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.start_button = tk.Button(self.control_frame, text="Start HID Firewall", command=self.start_firewall, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.start_button.pack(side="left", padx=10)

        self.stop_button = tk.Button(self.control_frame, text="Stop HID Firewall", command=self.stop_firewall, state=tk.DISABLED, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.stop_button.pack(side="left", padx=10)

        self.running = False
        self.listener = None



        """self.file_upload_frame = tk.LabelFrame(self.root,
        text="Analyze Kaggle Dataset", bg=self.style["highlight_bg"],
        fg=self.style["fg"], font=self.style["font"])
                self.file_upload_frame.pack(fill="both", expand="yes", padx=10, pady=10)

        self.file_upload_button = tk.Button(
                self.file_upload_frame,
                text="Browse and Analyze File",
                command=self.browse_and_analyze_kaggle_file,
                font=self.style["font"],
                bg=self.style["button_bg"],
                fg=self.style["button_fg"]
            )
        self.file_upload_button.pack(pady=10)"""

    def list_usb_devices(self):
        """List and analyze USB devices."""
        devices = device_detection.detect_usb_devices()
        self.device_analysis_results = []

        device_list = device_detection.list_usb_devices(devices)
        self.usb_list.config(state='normal')
        self.usb_list.delete('1.0', tk.END)

        for device in device_list:
            self.usb_list.insert(tk.END, f"Device: {device}\n")

            analysis_result =sandbox_analysis.analyze_usb_device_sandbox(device)
            self.device_analysis_results.append((device, analysis_result))

            if analysis_result['status'] == 'malicious':
                self.usb_list.insert(tk.END, f"🔴 Sandbox Alert:{analysis_result['details']}\n", "highlight")
                enforce_security("lock_system", duration=2)  # Lock the system if malicious USB is detected
                self.show_custom_alert("USB Alert", "Malicious USB detected! System locked.", "warning")

        self.usb_list.config(state='disabled')

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

            # Use the alias function name to avoid recursion issues
            if intercept_keystroke(decrypted, keystroke_vectorizer, keystroke_clf):  
                results.append(f"🚫 Malicious: {line}")
            else:
                results.append(f"✅ Benign: {line}")

        # Display results in the GUI
        self.show_custom_alert("Analysis Results", "\n".join(results), "info")



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

    def create_usb_frame(self):
        """Create a frame to display USB device information with scrolling support."""

        # Frame for USB devices with scrollbar
        self.usb_frame = tk.LabelFrame(self.root, text="Detected USB Devices", font=self.style["font"], bg=self.style["highlight_bg"],fg=self.style["fg"])
        self.usb_frame.pack(fill="both", expand=True, padx=10, pady=10)

        # Use self. to make variables accessible throughout the class
        self.usb_canvas = tk.Canvas(self.usb_frame, bg="white")
        self.scrollbar = tk.Scrollbar(self.usb_frame,orient="vertical", command=self.usb_canvas.yview)

        # Frame inside the canvas for content
        self.usb_content_frame = tk.Frame(self.usb_canvas, bg="white")

        # Configure canvas
        self.usb_canvas.create_window((0, 0),window=self.usb_content_frame, anchor="nw")
        self.usb_canvas.configure(yscrollcommand=self.scrollbar.set)

        # Layout
        self.usb_canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        # Scrolled text widget inside the frame
        self.usb_list = scrolledtext.ScrolledText(self.usb_content_frame, height=20,font=self.style["font"], bg="white", fg="black", wrap="word")
        self.usb_list.pack(fill="both", expand=True)

        # Ensure the scrolling works dynamically
        self.usb_content_frame.bind("<Configure>", lambda e: self.usb_canvas.configure(scrollregion=self.usb_canvas.bbox("all")))

        # Add Refresh Button
        self.refresh_button = tk.Button(self.usb_frame, text="Refresh Devices", command=self.list_usb_devices, font=self.style["font"], bg=self.style["button_bg"], fg=self.style["button_fg"])
        self.refresh_button.pack(side="bottom", pady=5)



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
                self.malicious_keystroke_detected = True  # Mark that a malicious keystroke was found
                enforcer.enforce_security("block_input", duration=5)

            if analyze_keystroke_partial(keystroke,self.keystroke_vectorizer, self.keystroke_clf):
                self.keystroke_list.insert(tk.END, f'Malicious detected: {keystroke}\n', 'highlight')
                self.malicious_keystroke_detected = True  # Mark that a malicious keystroke was found
                enforcer.enforce_security("block_input", duration=5)

            if analyze_keystroke(decrypted_keystroke,self.keystroke_vectorizer, self.keystroke_clf):
                self.keystroke_list.insert(tk.END, 'Blocking input for 5 seconds...\n', 'highlight')
                self.malicious_keystroke_detected = True  # Mark that a malicious keystroke was found
                enforcer.enforce_security("block_input", duration=5)# Use enforcer to block input
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
        self.keystroke_list.insert(tk.END, 'HID Firewall Started...\n', 'highlight')

        # Start keystroke listener in a separate thread
        self.listener_thread = threading.Thread(target=keystroke_interception.start_listener)
        self.listener_thread.start()



    def stop_firewall(self):
        """Stop the HID firewall and display the results."""
        
        # Stop the firewall and listener
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

        if self.listener:
            self.listener.stop()
            self.listener = None

        self.keystroke_list.insert(tk.END, 'HID Firewall Stopped...\n', 'highlight')

        # 🛡️ Check for malicious USB devices and keystrokes
        malicious_usb_detected = any(result for _, result in self.device_analysis_results if result == "malicious")

        # ✅ Check if malicious keystrokes were detected
        if self.malicious_keystroke_detected or malicious_usb_detected:
            # Show warning alert if either malicious keystrokes or USB are detected
            self.show_custom_alert(
                "Security Alert",
                "⚠️ Malicious activity detected (Keystroke or USB)! Immediate action is required to secure your system.",
                "warning"
            )
        else:
            # Show safe alert if no malicious activity is detected
            self.show_custom_alert(
                "USB Device Alert",
                "✅ All connected USB devices and keystrokes are safe. No malicious activity detected.",
                "info"
            )

        # Reset the malicious keystroke flag after stopping
        self.malicious_keystroke_detected = False


    def show_custom_alert(self, title, message, alert_type):
        alert = Toplevel(self.root)
        alert.title(title)
        alert.geometry("400x200")
        alert.configure(bg=self.style["bg"])

        msg_label = Label(alert, text=message, font=("Helvetica", 18,"bold"), bg=self.style["bg"], fg=self.style["fg"], wraplength=330)
        msg_label.pack(pady=20)

        if alert_type == "warning":
            msg_label.configure(fg="red")

        ok_button = Button(alert, text="OK", command=alert.destroy,font=self.style["font"], bg=self.style["button_bg"],fg=self.style["button_fg"])
        ok_button.pack(pady=10)


    def browse_and_analyze_kaggle_file(self):
        """
        Browse and select a file, then analyze it as a Kaggle dataset.
        """
        file_path = filedialog.askopenfilename(
            title="Select Kaggle Dataset File",
            filetypes=(("Excel Files", "*.xls;*.xlsx"), ("CSV Files","*.csv"), ("All Files", "*.*"))
        )
        if file_path:
            self.analyze_kaggle_file(file_path)


    def analyze_kaggle_file(self, file_path):
        """
        Analyze a Kaggle dataset file for malicious patterns.
        """
        try:
            if file_path.endswith((".csv", ".xls")):

                from models.train_kaggle_model import load_and_preprocess_kaggle_dataset, train_kaggle_model

                # Load and preprocess the dataset
                X, y = load_and_preprocess_kaggle_dataset(file_path)

                # Predict and analyze
                predictions = self.kaggle_model.predict(X)
                malicious_count = sum(predictions)
                total_files = len(predictions)

                # Show results in a popup
                result_text = (
                    f"Analyzed {total_files} files.\n"
                    f"Malicious files detected: {malicious_count}\n"
                    f"Benign files detected: {total_files - malicious_count}"
                )
                self.show_custom_alert("Kaggle File Analysis", result_text, "info")
            elif file_path.endswith(".txt"):
                # Handle unstructured text files
                with open(file_path, "r") as file:
                    lines = file.readlines()

                malicious_lines = []
                for line in lines:
                    line = line.strip()
                    if self.is_line_malicious(line):
                        malicious_lines.append(line)

                # Show results in a popup
                total_lines = len(lines)
                malicious_count = len(malicious_lines)
                result_text = (
                    f"Analyzed {total_lines} lines.\n"
                    f"Malicious lines detected: {malicious_count}\n"
                    f"Benign lines detected: {total_lines - malicious_count}"
                )
                self.show_custom_alert("Text File Analysis", result_text, "info")

            else:
            # Unsupported file type
                self.show_custom_alert("Error", "Unsupported file type. Please upload a .csv, .xls, .xlsx, or .txt file.", "error")

        except Exception as e:
            self.show_custom_alert("Error", f"Failed to analyze file: {e}", "error")


    def is_line_malicious(self, line):
        """
        Analyze a single line of text for malicious patterns.
        """
        # Preprocess the line
        processed_line = preprocess_content(line)

        # Analyze using Kaggle-trained model
        try:
            # Convert the line into a feature vector
            vector = self.kaggle_scaler.transform([processed_line])  #Ensure appropriate preprocessing
            prediction = self.kaggle_model.predict(vector)
            return prediction[0] == 1  # Malicious if label == 1
        except Exception as e:
            print(f"Error analyzing line: {e}")
            return False



if __name__ == "__main__":
    root = tk.Tk()
    app = HIDFirewallApp(root)
    root.mainloop()