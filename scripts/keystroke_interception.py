# File: scripts/keystroke_interception.py
from scripts.malicious_input_engine import load_keystroke_model,load_payload_model, is_malicious_ml
from pynput.keyboard import Key, Listener
import os

vectorizer, clf = load_keystroke_model()
vectorizer, clf = load_payload_model()
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
            print()
            print(f"Detected command: {command}")
            typed_command = []

            # Analyze the command
            if is_malicious_ml(command, vectorizer, clf):
                print(f"Malicious command detected: {command}")
            else:
                print(f"Command is benign: {command}")
    except Exception as e:
        print(f"Error processing key: {e}")

        
def write_file(keys):
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
    if key == Key.esc:
        return False

def start_listener():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    start_listener()


