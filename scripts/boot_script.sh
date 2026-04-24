Below is an example boot script written in BASH that you can place (for example) in /usr/local/bin/boot_script.sh. You should then create a corresponding systemd service that runs after networking is online. In this example the script does the following:

• Uses vmtoolsd (the VMware Tools command-line utility) to query the VM host for the hostname. (Adjust the command if you use a different virtual machine tools package.)  
• Constructs the full path to the YAML file based on the retrieved hostname.  
• Executes the rke2nodeinit script passing the YAML file and the -y flag.

Below is the boot script code:

--------------------------------------------------
```bash
#!/bin/bash
# boot_script.sh - Boot script to initialize rke2 node
# This script is intended to run after the networking services are up.

# Query the host using vmtoolsd to retrieve the VM hostname.
# Adjust the command below if you're using a different tool.
VM_HOSTNAME=$(vmtoolsd --cmd "info-get guestinfo.hostname")

if [[ -z "$VM_HOSTNAME" ]]; then
  echo "Error: Unable to retrieve VM hostname from host."
  exit 1
fi

# Export the hostname as a global variable if needed by other scripts.
export VM_HOSTNAME

# Formulate the path to the YAML file for rke2nodeinit.
# Example: /home/adminlocal/preprod/k8s/dc1domain/dc1domain-ctrl01.yaml
YAML_FILE="/home/adminlocal/preprod/k8s/dc1domain/${VM_HOSTNAME}.yaml"

if [[ ! -f "$YAML_FILE" ]]; then
  echo "Error: YAML file not found at $YAML_FILE"
  exit 1
fi

# Execute the rke2nodeinit script with the YAML file and the -y flag.
# Adjust the path to rke2nodeinit.sh if necessary.
SCRIPT_PATH="/path/to/rke2nodeinit.sh"

if [[ ! -x "$SCRIPT_PATH" ]]; then
  echo "Error: rke2nodeinit script not found or not executable at $SCRIPT_PATH"
  exit 1
fi

# Execute the command.
"$SCRIPT_PATH" -f "$YAML_FILE" -y

# Optionally, log the execution.
echo "rke2nodeinit executed with $YAML_FILE as configuration."
```
--------------------------------------------------

To ensure this boot script runs after networking is online, create a systemd service file like the following:

--------------------------------------------------
```ini
[Unit]
Description=Run boot script for rke2 node initialization
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/boot_script.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
--------------------------------------------------

Place the service file in /etc/systemd/system (e.g., as rke2nodeinit.service) and then enable it with:

--------------------------------------------------
```bash
sudo systemctl daemon-reload
sudo systemctl enable rke2nodeinit.service
```
--------------------------------------------------

This setup ensures that when the machine boots and after networking is established, the script queries the VM hostname using the virtual machine tools, builds the appropriate command line for rke2nodeinit, and executes the initialization script with the correct configuration file.
