# HID Firewall Project

## Overview

The **HID Firewall Project** is a security-focused application designed to detect and block malicious input from Human Interface Devices (HIDs) such as USB keyboards. It logs keystrokes in real-time, detects connected USB devices, and analyzes keystrokes for potential malicious activity using a trained machine learning model.

The project is built using Python and includes cross-platform support for Linux, Windows, and macOS. Key features include:
- **USB Device Detection**: Lists connected USB devices.
- **Keystroke Interception**: Logs keystrokes to a file.
- **Malicious Keystroke Detection**: Analyzes keystrokes using both regex matching and a trained machine learning model to detect malicious behavior.
- **Encryption of Logs**: Logs keystrokes securely with encryption.
- **GUI Integration**: A user-friendly graphical interface for interacting with the HID Firewall.

---

## **Table of Contents**
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Folder Structure](#folder-structure)
- [Usage](#usage)
  - [Training the Model](#training-the-model)
  - [Running the GUI Application](#running-the-gui-application)
- [Running Tests](#running-tests)
- [Packaging for Distribution](#packaging-for-distribution)
- [Cross-Platform Considerations](#cross-platform-considerations)
- [Security Enhancements](#security-enhancements)
- [Known Issues](#known-issues)
- [Contributors](#contributors)

---

## **Features**

- **Cross-Platform Compatibility**: Works on Windows, macOS, and Linux for USB device detection and keystroke logging.
- **Keystroke Logging**: Captures keystrokes and stores them in a log file.
- **Malicious Input Detection**: Uses a trained machine learning model to identify malicious keystrokes.
- **GUI**: A simple GUI built with `tkinter` to interact with the firewall.
- **Real-Time USB Device Detection**: Lists connected USB devices in real-time.
- **Encryption**: Logs are encrypted for security (optional).

---


---

## **Installation**

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/yourusername/hid-firewall.git
   cd hid-firewall
   ```

2. **Create a Virtual Environment (Optional)**:

   Create and activate a virtual environment to isolate the project's dependencies.

   ```bash
   python -m venv hid
   source hid/bin/activate  # Linux/macOS
   hid\Scripts\activate     # Windows
   ```

3. **Install Dependencies**:

   Install all necessary dependencies using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

4. **Ensure the `data` Directory Exists**:

   Create a `data/` folder to store the logs and CSV files:

   ```bash
   mkdir data
   ```

---

## **Folder Structure**

The project structure looks like this:

```
HID_Firewall_Project/
│
├── data/                               # Stores the keystrokes.csv and log files
│   ├── keystrokes.csv                  # CSV file with keystroke data for training
│   └── log.txt                         # Keystroke log file
│
├── models/                             # Stores trained machine learning models
│   ├── keystroke_model.pkl             # Trained model saved in pickle format
│   └── train_model.py                  # Script to train the model using keystrokes.csv
│
├── scripts/                            # Contains all scripts for device detection, keystroke logging, etc.
│   ├── device_detection.py             # Detects connected USB devices
│   ├── keystroke_interception.py       # Logs keystrokes
│   ├── malicious_input_engine.py       # Loads model and analyzes keystrokes
│   ├── encryption.py                   # (Optional) Encryption utilities for secure logging
│
├── tests/                              # Unit tests for various components
│   ├── test_analysis.py                # Tests for malicious input engine
│   ├── test_interception.py            # Tests for keystroke interception
│
├── requirements.txt                    # List of dependencies
├── README.md                           # This README file
├── hid_firewall_gui.py                 # Main GUI for the HID Firewall application
└── .gitignore                          # Git ignore file
```

---

## **Usage**

### **Training the Model**

Before running the application, you need to train the machine learning model using `keystrokes.csv`.

1. Ensure the `keystrokes.csv` file exists in the `data/` directory with the following structure:

   ```
   command,label
   "echo bad",1
   "rm -rf /",1
   "dd if=/dev/zero of=/dev/sda",1
   "ls -la",0
   "cat /etc/passwd",0
   ```

2. Train the model:

   ```bash
   python models/train_model.py
   ```

This will generate a `keystroke_model.pkl` file in the `models/` directory, which will be used for detecting malicious input.

### **Running the GUI Application**

1. After training the model, you can start the main GUI application:

   ```bash
   python hid_firewall_gui.py
   ```

2. **Features in the GUI**:
   - **USB Detection**: Lists all connected USB devices.
   - **Keystroke Interception**: Logs keystrokes in real-time.
   - **Malicious Detection**: Detects and blocks malicious keystrokes.

---

## **Running Tests**

You can run the unit tests to ensure that all components are functioning correctly. Use the following command to run all tests:

```bash
python -m unittest discover tests/
```

---

## **Packaging for Distribution**

You can package this project into an executable for easier distribution using `PyInstaller`.

1. Install `PyInstaller`:

   ```bash
   pip install pyinstaller
   ```

2. Create a standalone executable:

   ```bash
   pyinstaller --onefile hid_firewall_gui.py
   ```

The executable will be placed in the `dist/` directory, and you can distribute this file for other users to run without needing Python installed.

---


## **Cross-Platform Considerations**

This project is designed to work on Windows, Linux, and macOS. However, certain features (like USB detection) use platform-specific commands:
- **Windows**: Uses PowerShell commands for device detection.
- **Linux**: Uses `lsusb` for USB device detection.
- **macOS**: Uses `system_profiler` for detecting connected USB devices.

Ensure that the appropriate tools are available on your system for device detection to work.

---

## **Security Enhancements**

- **Log Encryption**: If needed, you can enable encryption for logs in `keystroke_interception.py` by integrating the `encryption.py` script.
- **Input Blocking**: The application can block malicious input using the enforcement features in `malicious_input_engine.py`.

---

## **Known Issues**

- **Model Not Found**: If you see an error that the model file (`keystroke_model.pkl`) is missing, ensure that you’ve successfully trained the model using `train_model.py`.
- **Cross-Platform USB Detection**: USB detection relies on platform-specific commands, so make sure the correct utilities are installed (`lsusb`, PowerShell, etc.).

---



