import tempfile
import subprocess
import os
import logging

# Configure logging
logging.basicConfig(
    filename="sandbox_analysis.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def execute_in_docker_sandbox(command, sandbox_type="generic"):
    """
    Execute a command or analyze input in a Docker sandbox environment.
    """
    try:
        # Create a temporary working directory
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_file_path = os.path.join(temp_dir, f"{sandbox_type}_input.txt")

            # Write the input to a temporary file
            with open(temp_file_path, "w") as temp_file:
                temp_file.write(command)

            # Run the Docker container and mount the temporary directory
            result = subprocess.run(
                [
                    "docker", "run", "--rm",
                    "-v", f"{temp_dir}:/sandbox",  # Mount temp_dir to /sandbox in the container
                    "sandbox_image",  # Docker image name
                    "cat", f"/sandbox/{os.path.basename(temp_file_path)}"
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Log the analysis details
            logging.info(f"Docker Sandbox Execution: {sandbox_type} input executed.")
            logging.info(f"Output: {result.stdout}")
            logging.info(f"Errors: {result.stderr}")

            # Example: Check for suspicious patterns in output
            if "malicious" in result.stdout.lower():
                return {"status": "malicious", "details": "Detected malicious behavior in sandbox."}

            return {"status": "safe", "details": "No malicious behavior detected."}
    except Exception as e:
        logging.error(f"Error during Docker sandbox execution: {e}")
        return {"status": "error", "details": str(e)}

def analyze_keystroke_sandbox(keystroke):
    """
    Analyze a keystroke in a Docker sandbox environment.
    """
    return execute_in_docker_sandbox(keystroke, sandbox_type="keystroke")

def analyze_usb_device_sandbox(device_info):
    """
    Analyze a USB device file content in a Docker sandbox environment.
    """
    return execute_in_docker_sandbox(device_info, sandbox_type="usb_device")

def analyze_usb_files_with_docker(mount_point):
    """
    Analyze all files in a USB mount point using Docker sandbox.
    """
    results = []
    try:
        for root, dirs, files in os.walk(mount_point):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', errors='ignore') as f:
                        content = f.read()
                        result = execute_in_docker_sandbox(content, sandbox_type="usb_file")
                        results.append((file_path, result))
                except Exception as e:
                    logging.error(f"Error reading file {file_path}: {e}")
    except Exception as e:
        logging.error(f"Error scanning USB content at {mount_point}: {e}")
    return results

if __name__ == "__main__":
    # Example usage for keystroke analysis
    keystroke_result = analyze_keystroke_sandbox("chmod +x bad_script.sh")
    print(keystroke_result)

    # Example usage for USB device analysis
    usb_device_result = analyze_usb_device_sandbox("Fake USB Device Info")
    print(usb_device_result)

    # Example usage for analyzing USB files
    usb_file_results = analyze_usb_files_with_docker("/media/username/USBDevice")
    for file_path, analysis_result in usb_file_results:
        print(f"File: {file_path}, Result: {analysis_result}")
