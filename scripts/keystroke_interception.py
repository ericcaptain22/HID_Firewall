
from scripts.malicious_input_engine import load_keystroke_model, analyze_keystroke, generate_ngrams
from pynput.keyboard import Key, Listener
from scripts.enforcer import enforce_security
import os
import sys
import subprocess

current_dir = os.path.dirname(os.path.abspath(__file__))
project_base_dir = os.path.abspath(os.path.join(current_dir, '..'))

if project_base_dir not in sys.path:
    sys.path.append(project_base_dir)

keystroke_vectorizer, keystroke_clf = load_keystroke_model()

count = 0
keys = []
typed_command = []

def on_press(key):
    """Handle intercepted keystrokes."""
    global keys, count, typed_command

    keys.append(str(key))
    count += 1

    if count >= 10:
        count = 0
        write_file(keys)
        keys = []

    try:
        if hasattr(key, 'char') and key.char:
            typed_command.append(key.char)
        elif key == Key.space:
            typed_command.append(' ')
        elif key == Key.enter:
            command = ''.join(typed_command).strip()
            print(f"\nDetected command: {command}")
            typed_command = []

            processed_command = preprocess_command(command)

            if analyze_command_ngrams(processed_command):
                print(f"🚫 Malicious command detected: {processed_command}")
                enforce_security("block_input", duration=5)
                enforce_security("terminate_processes")  # Terminate malicious process
                enforce_security("disconnect_device")  # Disconnect malicious USB

            else:
                print(f"✅ Benign command: {processed_command}")

    except Exception as e:
        print(f"Error processing key: {e}")

def preprocess_command(command):
    """Preprocess command string."""
    return command.strip().lower()

def analyze_command_ngrams(command):
    """Analyze command n-grams."""
    ngrams = generate_ngrams(command)

    for ngram in ngrams:
        if analyze_keystroke(ngram, keystroke_vectorizer, keystroke_clf):
            print(f"⚠️ Malicious n-gram detected: {ngram}")
            return True
    return False

def write_file(keys):
    """Log captured keystrokes."""
    log_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    os.makedirs(log_dir, exist_ok=True)

    log_file_path = os.path.join(log_dir, 'log.txt')

    with open(log_file_path, "a") as f:
        for key in keys:
            k = str(key).replace("'", "")
            f.write(f"{k} ")

def execute_command(command):
    """     Execute benign commands only.     """
    try:
        print(f"✅ Executing benign command: {command}")
        result = subprocess.run(command, shell=True,
capture_output=True, text=True)
        print(f"Command Output:\n{result.stdout}")

    except Exception as e:
        print(f"Error executing command: {e}")



def on_release(key):
    """Stop listener on ESC."""
    if key == Key.esc:
        return False

def start_listener():
    """Start keyboard listener."""
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    start_listener()
