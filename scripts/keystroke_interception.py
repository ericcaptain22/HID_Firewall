# File: scripts/keystroke_interception.py
from scripts.malicious_input_engine import load_keystroke_model, analyze_keystroke, generate_ngrams
from pynput.keyboard import Key, Listener
import os
import sys

current_dir = os.path.dirname(os.path.abspath(__file__))
project_base_dir = os.path.abspath(os.path.join(current_dir, '..'))
if project_base_dir not in sys.path:
    sys.path.append(project_base_dir)
    
# Load the trained keystroke model involved
keystroke_vectorizer, keystroke_clf = load_keystroke_model()

count = 0
keys = []
typed_command = []

def on_press(key):
    global keys, count, typed_command
    keys.append(str(key))          
    count += 1
    if count >= 10:  # Save to log file after 10 key presses
        count = 0
        write_file(keys)
        keys = []
    try:
        # Record alphanumeric keys
        if hasattr(key, 'char') and key.char:
            typed_command.append(key.char)
        elif key == Key.space:
            typed_command.append(' ')
        elif key == Key.enter:
            # Command is complete
            command = ''.join(typed_command).strip()
            print(f"\nDetected command: {command}")
            typed_command = []

            # Preprocess and analyze the command
            processed_command = preprocess_command(command)
            if analyze_command_ngrams(processed_command):
                print(f"Malicious command detected: {processed_command}")
            else:
                print(f"Command is benign: {processed_command}")
    except Exception as e:
        print(f"Error processing key: {e}")

def preprocess_command(command):
    """Preprocess the command."""
    return command.strip().lower()

def analyze_command_ngrams(command):
    """Analyze command n-grams for malicious patterns."""
    ngrams = generate_ngrams(command)
    for ngram in ngrams:
        if analyze_keystroke(ngram, keystroke_vectorizer, keystroke_clf):
            print(f"Malicious n-gram detected: {ngram}")
            return True
    return False

def write_file(keys):
    """Write captured keystrokes to a log file."""
    # Ensure the log directory exists
    log_dir = os.path.join(os.path.dirname(__file__), '..', 'data')
    os.makedirs(log_dir, exist_ok=True)

    # Log file path
    log_file_path = os.path.join(log_dir, 'log.txt')

    # Write keystrokes to log file
    with open(log_file_path, "a") as f:
        for key in keys:
            k = str(key).replace("'", "")
            if k.find("space") > 0:
                f.write(" ")
            elif k.find("Key") == -1:
                f.write(k)
            elif k.find("enter") > 0:
                f.write("\n")

def on_release(key):
    """Handle key release events."""
    if key == Key.esc:
        return False

def start_listener():
    """Start the keyboard listener."""
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    start_listener()
