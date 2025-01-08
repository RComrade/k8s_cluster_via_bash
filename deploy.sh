#!/bin/bash

# Colors
GREEN="\033[1;32m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;34m"
CYAN="\033[1;36m"
RESET="\033[0m"

# File variables
DOWNLOADS_FILE="downloads.txt"
MACHINES_FILE="machines.txt"
TMP_HOSTS="tmp_hosts.txt"
CA_CONF_FILE="ca.conf"

# Version variables
K8S_STABLE_VERSION_URL="https://dl.k8s.io/release/stable.txt"
K8S_VERSION=$(curl -sL "$K8S_STABLE_VERSION_URL" | sed 's/^v//')
CONTAINERD_V="2.0.0"
CRICTL_V="1.31.1"
CNI_V="1.6.0"
RUNC_V="1.2.1"
ETCD_V="3.4.34"

# Misc variables
EDITOR="nano"

# Welcome menu
function display_welcome() {
    echo -e "${GREEN}Hello, this is a bash script that will deploy k8s in a hard way.${RESET}"
    echo -e "${YELLOW}The prerequisites are:${RESET}"
    echo -e "${BLUE}* Your system must be a debian-like${RESET}"
    echo -e "${BLUE}* Each host should have the same user credentials${RESET}"
    echo -e "${BLUE}* The user should be in a sudo group${RESET}"
    echo -e "${BLUE}* The default text editor is $EDITOR, might be changed in the very beginning of this script${RESET}"
    echo -e "${BLUE}* In the current folder there should be a text file with a list of hosts that'll act as k8s controllers and workers${RESET}"
    echo -e "${BLUE}* If there is no such file, we generate one during the installation process${RESET}"
    echo -e "${BLUE}* The script is about to install additional software as well, if it is not installed${RESET}"
    echo -e "${CYAN}*** The original idea comes from here -> https://github.com/kelseyhightower/kubernetes-the-hard-way${RESET}"
    echo -e "${CYAN}*** Find more documentation here -> https://github.com/RComrade/k8s_cluster_via_bash/blob/master/README.md${RESET}"
    echo
}

# Get user credentials
function get_credentials() {
    read -p "Enter the username to access the nodes: " USERNAME
    read -sp "Enter sudo password for the account: " SUDO_PASSWORD
    echo # Newline
}

# OS check
function check_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "debian" && "$ID" != "ubuntu" ]]; then
            echo "This script is intended for Debian-based systems only. Detected OS: $ID"
            exit 1
        fi
    else
        echo "Unable to determine the operating system. This script supports only Debian-based systems."
        exit 1
    fi
}

# Detect system architecture
function get_architecture() {
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            SYSTEM_ARCH="amd64"
            ;;
        aarch64)
            SYSTEM_ARCH="arm64"
            ;;
        *)
            SYSTEM_ARCH="unknown"
            ;;

    esac
    echo -e "The system architecture is:${YELLOW} $SYSTEM_ARCH ${RESET}" 
}

# Check and install required packages
function check_required_packages() {
    REQUIRED_PACKAGES=("wget" "curl" "nano" "openssl" "sshpass")
    MISSING_PACKAGES=()

    # Checking installed packages
    for PACKAGE in "${REQUIRED_PACKAGES[@]}"; do
        if ! command -v $PACKAGE &> /dev/null; then
            MISSING_PACKAGES+=($PACKAGE)
        fi
    done

    # if there are missing packages
    if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
        echo -e "${RED}The following required packages are missing:${RESET}"
        for PACKAGE in "${MISSING_PACKAGES[@]}"; do
            echo -e "${BLUE}$PACKAGE${RESET}"
        done

        echo -e "${BLUE}Installing missing packages...${RESET}"
        
        # Installation with sudo password
        echo "$SUDO_PASSWORD" | sudo -S apt-get update
        echo "$SUDO_PASSWORD" | sudo -S apt-get install -y "${MISSING_PACKAGES[@]}"
        
        # Checking if the packages are installed
        for PACKAGE in "${MISSING_PACKAGES[@]}"; do
            if ! command -v $PACKAGE &> /dev/null; then
                echo -e "${RED}Failed to install $PACKAGE. Please check your system configuration.${RESET}"
                exit 1
            else
                echo -e "${GREEN}$PACKAGE was successfully installed.${RESET}"
            fi
        done
    else
        echo -e "${GREEN}All required packages are already installed.${RESET}"
    fi
}

function prompt_for_versions() {
    echo -e "Enter versions for the tools (press Enter to use default):"
    
    # Colored input
    echo -n -e "${CYAN}Kubernetes${RESET} version [default: $K8S_VERSION]: "
    read input
    K8S_VERSION="${input:-$K8S_VERSION}"

    echo -n -e "${CYAN}CRI Tools${RESET} version [default: $CRICTL_V]: "
    read input
    CRICTL_V="${input:-$CRICTL_V}"

    echo -n -e "${CYAN}runc${RESET} version [default: $RUNC_V]: "
    read input
    RUNC_V="${input:-$RUNC_V}"

    echo -n -e "${CYAN}CNI Plugins${RESET} version [default: $CNI_V]: "
    read input
    CNI_V="${input:-$CNI_V}"

    echo -n -e "${CYAN}containerd${RESET} version [default: $CONTAINERD_V]: "
    read input
    CONTAINERD_V="${input:-$CONTAINERD_V}"

    echo -n -e "${CYAN}etcd${RESET} version [default: $ETCD_V]: "
    read input
    ETCD_V="${input:-$ETCD_V}"

    echo -e "${GREEN}Versions set:${RESET}"
    echo -e "${CYAN}Kubernetes${RESET}: $K8S_VERSION"
    echo -e "${CYAN}CRI Tools${RESET}: $CRICTL_V"
    echo -e "${CYAN}runc${RESET}: v$RUNC_V"
    echo -e "${CYAN}CNI Plugins${RESET}: $CNI_V"
    echo -e "${CYAN}containerd${RESET}: $CONTAINERD_V"
    echo -e "${CYAN}etcd${RESET}: v$ETCD_V"

    cp downloads.example downloads.txt

    # Replace placeholders with actual values
    sed -i "s/\$K8S_VERSION/$K8S_VERSION/g" "$DOWNLOADS_FILE"
    sed -i "s/\$CRICTL_V/$CRICTL_V/g" "$DOWNLOADS_FILE"
    sed -i "s/\$RUNC_V/$RUNC_V/g" "$DOWNLOADS_FILE"
    sed -i "s/\$CNI_V/$CNI_V/g" "$DOWNLOADS_FILE"
    sed -i "s/\$CONTAINERD_V/$CONTAINERD_V/g" "$DOWNLOADS_FILE"
    sed -i "s/\$ETCD_V/$ETCD_V/g" "$DOWNLOADS_FILE"
    sed -i "s/\$SYSTEM_ARCH/$SYSTEM_ARCH/g" "$DOWNLOADS_FILE"

    echo -e "${GREEN}File $DOWNLOADS_FILE updated successfully.${RESET}"
}

# Function to validate the downloads file and check the URLs
function validate_downloads_file() {

    local RECREATE=false

    # Validate each URL in the file
    echo "Validating URLs in $DOWNLOADS_FILE..."
    while IFS=" " read -r tool_name file_url; do
        # Skip empty lines or malformed lines
        if [[ -z "$tool_name" || -z "$file_url" ]]; then
            continue
        fi

        if curl --head --silent --fail "$file_url" > /dev/null; then
            echo -e "${GREEN}[OK] $file_url${RESET}"
        else
            echo -e "${RED}[FAILED] $file_url${RESET}"
            RECREATE=true
        fi
    done < "$DOWNLOADS_FILE"

    # If any URL failed, ask if the user wants to edit the downloads file
    if [ "$RECREATE" = true ]; then
        echo -e "${RED}One or more URLs are invalid.${RESET}"
        echo -e "To proceed it is ${RED}required${RESET} to have valid URLs."
        echo -e "In case of a refusal to edit the downloads.txt, the script'll ${RED}stop${RESET} its work."
        read -p "Do you want to edit the downloads.txt file? (y/n): " EDIT
        if [[ "$EDIT" =~ ^[Yy]$ ]]; then
            echo "Opening downloads.txt for editing..."
            $EDITOR "$DOWNLOADS_FILE"

            # Re-run the validation after editing
            validate_downloads_file
        else
            echo -e "You chose ${RED}not to edit${RESET} the file. Good bye."
            exit 1
        fi
    else
        echo "All URLs are valid."
    fi
}

# Function to download files using the updated downloads.txt
function download_files() {
    DOWNLOADS_FILE="downloads.txt"

    # Check if downloads.txt exists
    if [ ! -f "$DOWNLOADS_FILE" ]; then
        echo -e "${RED}File $DOWNLOADS_FILE not found! Exiting.${RESET}"
        exit 1
    fi

    echo -e "${YELLOW}Starting file downloads...${RESET}"

    # Create the downloads directory if it doesn't exist
    mkdir -p downloads

    # Read each line from downloads.txt
    while IFS=" " read -r tool_name file_url; do
        # Skip empty lines or malformed lines
        if [[ -z "$tool_name" || -z "$file_url" ]]; then
            continue
        fi

        file_path="downloads/$tool_name"

        # Check if the file already exists in the downloads directory
        if [ -f "$file_path" ]; then
            echo -e "${GREEN}File $tool_name already exists. Skipping download.${RESET}"
        else
            echo -e "${YELLOW}Downloading $tool_name...${RESET}"

            # Download the file
            wget -q --show-progress \
                --https-only \
                --timestamping \
                -O "$file_path" \
                "$file_url"

            # Check the result of the download
            if [ $? -ne 0 ]; then
                echo -e "${RED}Failed to download $tool_name. Please check your connection.${RESET}"
                exit 1
            fi
        fi
    done < "$DOWNLOADS_FILE"

    echo -e "${GREEN}All files downloaded successfully.${RESET}"
}

# Function to install kubectl using sudo
function install_kubectl() {
    KUBECTL_PATH="downloads/kubectl"

    # Check if the kubectl file exists in the downloads directory
    if [ ! -f "$KUBECTL_PATH" ]; then
        echo -e "${RED}File kubectl not found in downloads directory! Exiting.${RESET}"
        exit 1
    fi

    # Give execute permissions to the file
    chmod +x "$KUBECTL_PATH"

    # Copy the file to /usr/local/bin using sudo
    echo "$SUDO_PASSWORD" | sudo -S cp "$KUBECTL_PATH" /usr/local/bin/

    # Check if the copy operation was successful
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}kubectl installed successfully!${RESET}"
    else
        echo -e "${RED}Failed to install kubectl. Please check your permissions.${RESET}"
        exit 1
    fi

    # Get the kubectl version, color the version numbers and remove KustomizeVersion
    kubectl version --client | sed -E 's/Client Version:/\n&/' | sed "s/ //g" \
        | sed "s/\(v[0-9]*\.[0-9]*\.[0-9]*\)/\x1b[32m\1\x1b[0m/"  # Display version in green
}

# Function to check or create machines.txt
function check_machines_file() {
    
    # Check if machines.txt exists
    if [ -f "$MACHINES_FILE" ]; then
        echo -e "${GREEN}File $MACHINES_FILE found. Below is its content:${RESET}"
        
        echo -e "${CYAN}============================${RESET}"
        cat "$MACHINES_FILE"
        echo -e "${CYAN}============================${RESET}"

        # Confirm with the user
        echo -e "${GREEN}y${RESET} - ${CYAN}continue${RESET} with the existing configuration "
        echo -e "${RED}n${RESET} - ${CYAN}$EDITOR${RESET} will be opened for editing "
        echo -e -n "(y/n?): "
        read input
        if [[ "$input" == "y" ]]; then
            echo -e "${GREEN}Continuing with the existing configuration.${RESET}"
            return
        else
            echo -e "${CYAN}Opening $MACHINES_FILE for editing...${RESET}"
            $EDITOR "$MACHINES_FILE"
            check_machines_file
            return
        fi
    else
        # If machines.txt doesn't exist, create a new one
        echo -e "${YELLOW}File $MACHINES_FILE not found. Creating a new one.${RESET}"
        create_machines_file
    fi
}

# Function to create machines.txt from scratch
function create_machines_file() {
    # Get domain name
    echo -n -e "Enter the ${CYAN}domain${RESET} for the Kubernetes network (default: ${CYAN}cluster.local${RESET}): "
    read input
    DOMAIN=${input:-cluster.local}

    # Get subnet for workers
    echo -n -e "Enter the base ${CYAN}worker node subnet${RESET} (default: ${CYAN}10.200.0.0/24${RESET}): "
    read input
    BASE_WORKER_SUBNET=${input:-10.200.0.0/24}

    # Get cluster IP range
    echo -n -e "Enter the ${CYAN}cluster node subnet${RESET} (default: ${CYAN}10.32.0.0/24${RESET}): "
    read input
    CLUSTER_IP_RANGE=${input:-10.32.0.0/24}

    # Extract base IP address and starting subnet
    BASE_WORKER_IP=$(echo $BASE_WORKER_SUBNET | cut -d '.' -f 1-2)
    START_WORKER_SUBNET=$(echo $BASE_WORKER_SUBNET | cut -d '/' -f 1 | cut -d '.' -f 3)

    # Get the number of controllers with input validation (at least 1)
    while true; do
        echo -n -e "Enter the number of ${CYAN}controllers${RESET} (at least 1): "
        read NUM_CONTROLLERS
        if [[ -n "$NUM_CONTROLLERS" && "$NUM_CONTROLLERS" =~ ^[0-9]+$ && "$NUM_CONTROLLERS" -ge 1 ]]; then
            break
        else
            echo -e "${RED}Invalid input! Please enter a valid number for the number of controllers (at least 1).${RESET}"
        fi
    done

    # Initialize machines.txt
    MACHINES_FILE="machines.txt"
    > "$MACHINES_FILE"

    # Loop for controller entries
    for ((i=0; i<$NUM_CONTROLLERS; i++)); do
        # Get controller IPv4 and hostname
        echo -n -e "Enter the ${GREEN}IPv4${RESET} address for ${CYAN}controller-$i${RESET}: "
        read CONTROLLER_IP
        echo -n -e "Enter the ${GREEN}hostname${RESET} for ${CYAN}controller-$i${RESET}: "
        read CONTROLLER_HOSTNAME

        # Form and write controller entry to machines.txt
        echo "controller-$i $CONTROLLER_IP $CONTROLLER_HOSTNAME.$DOMAIN $CONTROLLER_HOSTNAME $CLUSTER_IP_RANGE" >> "$MACHINES_FILE"
    done

    # Get the number of worker nodes with input validation (at least 1)
    while true; do
        echo -n -e "Enter the number of ${CYAN}worker${RESET} nodes (at least 1): "
        read NUM_WORKERS
        if [[ -n "$NUM_WORKERS" && "$NUM_WORKERS" =~ ^[0-9]+$ && "$NUM_WORKERS" -ge 1 ]]; then
            break
        else
            echo -e "${RED}Invalid input! Please enter a valid number for the number of worker nodes (at least 1).${RESET}"
        fi
    done

    # Loop for worker entries
    for ((i=0; i<$NUM_WORKERS; i++)); do
        # Calculate subnet for the worker node
        WORKER_SUBNET=$(($START_WORKER_SUBNET + $i))

        # Get worker IPv4 and hostname
        echo -n -e "Enter the ${GREEN}IPv4${RESET} address for ${CYAN}worker-$i${RESET}: "
        read WORKER_IP
        echo -n -e "Enter the ${GREEN}hostname${RESET} for ${CYAN}worker-$i${RESET}: "
        read WORKER_HOSTNAME

        # Form and write worker entry to machines.txt
        WORKER_SUBNET_CIDR="$BASE_WORKER_IP.$WORKER_SUBNET.0/24"
        echo "worker-$i $WORKER_IP $WORKER_HOSTNAME.$DOMAIN $WORKER_HOSTNAME $WORKER_SUBNET_CIDR" >> "$MACHINES_FILE"
    done

    check_machines_file
}

# Function to check the availability of a specific controller
function check_availability() {
    local IP=$1
    local HOSTNAME=$2

    echo -n "Pinging $HOSTNAME ($IP)... "
    # Perform the ping check
    ping -c 3 "$IP" &> /dev/null
    if [ $? -eq 0 ]; then
        echo "Success!"
    else
        echo "Failed!"
        echo -e "${RED}Node $HOSTNAME ($IP) is not reachable.${RESET}"
        
        # Ask the user if they want to edit the machines.txt
        read -p "Do you want to edit machines.txt and fix the issue? (y/n): " EDIT
        if [[ "$EDIT" =~ ^[Yy]$ ]]; then
            echo "Opening machines.txt for editing..."
            $EDITOR "$MACHINES_FILE"
            
            # After editing, recheck the controller's availability
            check_availability "$IP" "$HOSTNAME"
        fi
    fi
}

function adding_remote_nodes_to_hosts_file() {
    local IPv4=$1
    local FQDN=$2
    local HOSTNAME=$3
    
    # Сохраняем запись в tmp_hosts
    echo "$IPv4 $FQDN $HOSTNAME" | sudo tee -a "$TMP_HOSTS"

    # Проверка на наличие записи в /etc/hosts, чтобы избежать дублирования
    if ! grep -q "$IPv4 $FQDN $HOSTNAME" /etc/hosts; then
        # Добавляем содержимое tmp_hosts в /etc/hosts
        cat "$TMP_HOSTS" | sudo tee -a /etc/hosts
        echo "Added $IPv4 $FQDN $HOSTNAME to /etc/hosts"
    else
        echo "Entry for $IPv4 $FQDN $HOSTNAME already exists in /etc/hosts"
    fi

    # Удаляем временный файл tmp_hosts
    
}

function update_remote_hosts_file() {
    local FQDN=$1
    local HOST=$2

    # Execute commands on the remote machine using sshpass
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -n "$USERNAME@$FQDN" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
        # Check and add entries for localhost if not already present
        if ! grep -q \"127.0.0.1 $FQDN $HOST\" /etc/hosts; then
            echo \"127.0.0.1 $FQDN $HOST\" | tee -a /etc/hosts
        fi
        if ! grep -q \"127.0.1.1 $FQDN $HOST\" /etc/hosts; then
            echo \"127.0.1.1 $FQDN $HOST\" | tee -a /etc/hosts
        fi
    '"

    # Copy the tmp_hosts file to the remote machine
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp "$TMP_HOSTS" "$USERNAME@$FQDN:/home/$USERNAME/tmp_hosts"

    # Append tmp_hosts content to /etc/hosts on the remote machine, avoiding duplicates
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -n "$USERNAME@$FQDN" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
        while IFS= read -r line; do
            if ! grep -Fxq \"\$line\" /etc/hosts; then
                echo \"\$line\" | tee -a /etc/hosts
            fi
        done < /home/$USERNAME/tmp_hosts
        rm -f /home/$USERNAME/tmp_hosts
    '"

    echo "Updated /etc/hosts on $FQDN without duplicates"
}

# Function to generate SSH keys automatically
function generate_ssh_keys() {
    # Path to store the generated SSH key (default location)
    local SSH_KEY_PATH="$HOME/.ssh/id_rsa"
    
    # Check if the key already exists
    if [ -f "$SSH_KEY_PATH" ]; then
        echo "SSH key already exists at $SSH_KEY_PATH. Skipping generation."
    else
        # Generate SSH keys with default settings (no passphrase, default location)
        echo "Generating SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f "$SSH_KEY_PATH" -N "" &> /dev/null
        if [ $? -eq 0 ]; then
            echo "SSH key pair generated successfully."
            echo "Private key: $SSH_KEY_PATH"
            echo "Public key: $SSH_KEY_PATH.pub"
        else
            echo "Failed to generate SSH key pair."
        fi
    fi
}

function distribute_ssh_keys() {
    local FQDN=$1
    
    # Add the remote host to known_hosts using ssh-keyscan
    echo "Adding $FQDN to known_hosts..."
    ssh-keyscan -H "$FQDN" >> "/home/$USERNAME/.ssh/known_hosts"
    
    # Use sshpass to distribute the public key to the remote machine
    echo "Distributing SSH key to $FQDN..."
    sshpass -p "$SUDO_PASSWORD" ssh-copy-id -i "/home/$USERNAME/.ssh/id_rsa.pub" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "$USERNAME@$FQDN" &> /dev/null
    
    if [ $? -eq 0 ]; then
        echo "SSH key successfully copied to $FQDN."
    else
        echo "Failed to copy SSH key to $FQDN."
    fi
}

function create_ca_crt_and_key(){
# Генерация частного ключа для CA

openssl genrsa -out ca.key 4096
openssl req -x509 -new -sha512 -noenc -key ca.key -days 3653 -config ca.conf -out ca.crt

}

# Функция для добавления записей DNS в файл ca.conf
function add_controllers_to_ca_conf() {
    # Чтение файла machines.txt и извлечение FQDN для контроллеров
    grep 'controller' "$MACHINES_FILE" | while IFS=" " read -r ROLE IP FQDN HOSTNAME SUBNET; do
        # Проверяем, существует ли уже запись DNS для данного FQDN в файле
        if ! grep -q "$FQDN" "$CA_CONF_FILE"; then
            # Находим максимальный индекс DNS и увеличиваем его на 1
            local NEXT_DNS_INDEX=$(( $(grep -oP "^DNS\.\K\d+" "$CA_CONF_FILE" | sort -n | tail -n 1) + 1 ))

            # Добавляем строку DNS в конец файла ca.conf, гарантируя новую строку
            echo -e "DNS.$NEXT_DNS_INDEX = $FQDN" >> "$CA_CONF_FILE"
            echo "Добавлена запись: DNS.$NEXT_DNS_INDEX = $FQDN"
        else
            echo "Запись для $FQDN уже существует. Пропускаем."
        fi
    done
}

# Function to append worker-specific configuration to ca.conf if not already present
function add_worker_to_ca_conf() {
    local WORKER_HOSTNAME=$1

    # Check if the section for the hostname already exists in the ca.conf file
    if grep -q "^\[$WORKER_HOSTNAME\]" "$CA_CONF_FILE"; then
        echo "Configuration for $WORKER_HOSTNAME already exists in $CA_CONF_FILE. Skipping."
        return
    fi

    # Append the configuration to the ca.conf file; Starting with an empty line
    echo ""
    tee -a "$CA_CONF_FILE" > /dev/null << EOF

[$WORKER_HOSTNAME]
distinguished_name = ${WORKER_HOSTNAME}_distinguished_name
prompt             = no
req_extensions     = ${WORKER_HOSTNAME}_req_extensions

[${WORKER_HOSTNAME}_req_extensions]
basicConstraints     = CA:FALSE
extendedKeyUsage     = clientAuth, serverAuth
keyUsage             = critical, digitalSignature, keyEncipherment
nsCertType           = client
nsComment            = "$WORKER_HOSTNAME Certificate"
subjectAltName       = DNS:$WORKER_HOSTNAME, IP:127.0.0.1
subjectKeyIdentifier = hash

[${WORKER_HOSTNAME}_distinguished_name]
CN = system:node:$WORKER_HOSTNAME
O  = system:nodes
C  = US
ST = Washington
L  = Seattle
EOF

    echo "Configuration regarding $WORKER_HOSTNAME has been added to $CA_CONF_FILE."
}


function generate_common_certs {
    components=("admin" "kube-proxy" "kube-scheduler" "kube-controller-manager" "kube-api-server" "service-accounts")
    for component in "${components[@]}"; do
    openssl genpkey -algorithm RSA -out "${component}.key"
    openssl req -new -key "${component}.key" -sha256 -config "ca.conf" -section "${component}" -out "${component}.csr"
    openssl x509 -req -days 3653 -in "${component}.csr" -copy_extensions copyall -sha256 -CA "ca.crt" -CAkey "ca.key" -CAcreateserial -out "${component}.crt"
done
}

# Function to generate keys, CSR, and sign certificates for a worker node
function generate_worker_certificates() {
    local WORKER_HOSTNAME=$1
    local WORKER_ROLE=$2

    # Only process hostnames matching the pattern 'node-*'
    if [[ $WORKER_ROLE == worker-* ]]; then
        echo "Generating certificates for $WORKER_HOSTNAME..."

        # Generate private key
        openssl genpkey -algorithm RSA -out "${WORKER_HOSTNAME}.key"
        
        # Generate CSR using the specific section in ca.conf
        openssl req -new \
            -key "${WORKER_HOSTNAME}.key" \
            -sha256 \
            -config "ca.conf" \
            -section "${WORKER_HOSTNAME}" \
            -out "${WORKER_HOSTNAME}.csr"

        # Sign the CSR to create the certificate
        openssl x509 -req \
            -days 3653 \
            -in "${WORKER_HOSTNAME}.csr" \
            -copy_extensions copyall \
            -sha256 \
            -CA "ca.crt" \
            -CAkey "ca.key" \
            -CAcreateserial \
            -out "${WORKER_HOSTNAME}.crt"

        echo "Certificates generated for $WORKER_HOSTNAME: ${WORKER_HOSTNAME}.key, ${WORKER_HOSTNAME}.crt"
        echo "-----------------------------------"
    else
        echo "Skipping $WORKER_HOSTNAME as it does not match the pattern 'worker-*'."
    fi
}

# Function to distribute certificates to controller host
function distribute_controller_certs() {
    local CONTROLLER_HOSTNAME=$1

    echo "Distributing certificates to $CONTROLLER_HOSTNAME..."

    # Create the target directory on the remote host
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" "sudo -S mkdir -p /var/lib/kubelet/"

    # Using sudo to copy the certificates with root privileges
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no ca.crt "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no ca.key "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no kube-api-server.crt "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no kube-api-server.key "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no service-accounts.crt "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no service-accounts.key "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"

    echo "Certificates distributed successfully to $CONTROLLER_HOSTNAME."
}

# Function to distribute certificates to worker nodes
function distribute_worker_certs() {
    local WORKER_HOSTNAME=$1

    echo "Distributing certificates to $WORKER_HOSTNAME..."

    # Create the target directory on the remote host
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "sudo -S mkdir -p /var/lib/kubelet/"

    # Using sudo to copy the certificates with root privileges
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no ca.crt "$USERNAME@$WORKER_HOSTNAME:/tmp/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no "${WORKER_HOSTNAME}.crt" "$USERNAME@$WORKER_HOSTNAME:/tmp/kubelet.crt"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no "${WORKER_HOSTNAME}.key" "$USERNAME@$WORKER_HOSTNAME:/tmp/kubelet.key"

    # Copy to the final directory as root
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh "$USERNAME@$WORKER_HOSTNAME" "sudo -S mv /tmp/ca.crt /var/lib/kubelet/"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh "$USERNAME@$WORKER_HOSTNAME" "sudo -S mv /tmp/kubelet.crt /var/lib/kubelet/kubelet.crt"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" ssh "$USERNAME@$WORKER_HOSTNAME" "sudo -S mv /tmp/kubelet.key /var/lib/kubelet/kubelet.key"

    echo "Certificates distributed successfully to $WORKER_HOSTNAME."
}

# Function to generate configs for worker nodes
function generate_k8s_worker_configs(){
    local WORKER_HOSTNAME=$1

    generate_server_url
  
    kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=$SERVER_URL \
    --kubeconfig=${WORKER_HOSTNAME}.kubeconfig

    kubectl config set-credentials system:node:${WORKER_HOSTNAME} \
    --client-certificate=${WORKER_HOSTNAME}.crt \
    --client-key=${WORKER_HOSTNAME}.key \
    --embed-certs=true \
    --kubeconfig=${WORKER_HOSTNAME}.kubeconfig

    kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:node:${WORKER_HOSTNAME} \
    --kubeconfig=${WORKER_HOSTNAME}.kubeconfig

    kubectl config use-context default \
    --kubeconfig=${WORKER_HOSTNAME}.kubeconfig

    echo -e "${GREEN}Kubeconfig for $WORKER_HOSTNAME created successfully.${RESET}"
}

function generate_k8s_controller_configs(){
    local CONTROLLER_HOSTNAME=$1

    generate_server_url
    
    kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=$SERVER_URL \
    --kubeconfig=kube-proxy.kubeconfig

    kubectl config set-credentials system:kube-proxy \
    --client-certificate=kube-proxy.crt \
    --client-key=kube-proxy.key \
    --embed-certs=true \
    --kubeconfig=kube-proxy.kubeconfig

    kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-proxy \
    --kubeconfig=kube-proxy.kubeconfig

    kubectl config use-context default \
    --kubeconfig=kube-proxy.kubeconfig

    kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=$SERVER_URL \
    --kubeconfig=kube-controller-manager.kubeconfig

    kubectl config set-credentials system:kube-controller-manager \
    --client-certificate=kube-controller-manager.crt \
    --client-key=kube-controller-manager.key \
    --embed-certs=true \
    --kubeconfig=kube-controller-manager.kubeconfig

    kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-controller-manager \
    --kubeconfig=kube-controller-manager.kubeconfig

    kubectl config use-context default \
    --kubeconfig=kube-controller-manager.kubeconfig  

    kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=$SERVER_URL \
    --kubeconfig=kube-scheduler.kubeconfig

    kubectl config set-credentials system:kube-scheduler \
    --client-certificate=kube-scheduler.crt \
    --client-key=kube-scheduler.key \
    --embed-certs=true \
    --kubeconfig=kube-scheduler.kubeconfig

    kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=system:kube-scheduler \
    --kubeconfig=kube-scheduler.kubeconfig

    kubectl config use-context default \
    --kubeconfig=kube-scheduler.kubeconfig  

    kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=$SERVER_URL \
    --kubeconfig=admin.kubeconfig

   kubectl config set-credentials admin \
    --client-certificate=admin.crt \
    --client-key=admin.key \
    --embed-certs=true \
    --kubeconfig=admin.kubeconfig

  kubectl config set-context default \
    --cluster=kubernetes-the-hard-way \
    --user=admin \
    --kubeconfig=admin.kubeconfig

  kubectl config use-context default \
    --kubeconfig=admin.kubeconfig

}

# Function to generate SERVER_URL from controller-0's FQDN
function generate_server_url() {
    # Iterate over each line in the machines file
    while IFS=" " read -r ROLE IP FQDN HOSTNAME SUBNET; do
        if [[ "$ROLE" == "controller-0" ]]; then
            # Create SERVER_URL variable using FQDN of controller-0
            SERVER_URL="https://$FQDN:6443"
            break  # Exit the loop once the controller-0 is found
        fi
    done < "$MACHINES_FILE"

    # Return the SERVER_URL (or echo it to be used in the calling script)
    echo "$SERVER_URL"
}

# Function to distribute certificates to worker nodes
function distribute_kube_configs_to_workers(){
    local WORKER_HOSTNAME=$1
    echo -e "${GREEN}Copying kube configs to $WORKER_HOSTNAME...${RESET}"

    # Create dirs
    sshpass -p "$SUDO_PASSWORD" ssh -n -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S mkdir -p /var/lib/{kube-proxy,kubelet}"

    # Copy files to a tmp location
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no kube-proxy.kubeconfig "$USERNAME@$WORKER_HOSTNAME:/tmp/kube-proxy.kubeconfig"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no "${WORKER_HOSTNAME}.kubeconfig" "$USERNAME@$WORKER_HOSTNAME:/tmp/${WORKER_HOSTNAME}.kubeconfig"

    # Move files with superuser rights
    sshpass -p "$SUDO_PASSWORD" ssh -n -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S mv /tmp/kube-proxy.kubeconfig /var/lib/kube-proxy/kubeconfig"
    sshpass -p "$SUDO_PASSWORD" ssh -n -o StrictHostKeyChecking=no "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S mv /tmp/${WORKER_HOSTNAME}.kubeconfig /var/lib/kubelet/kubeconfig"

    echo -e "${GREEN}Files successfully copied to $WORKER_HOSTNAME.${RESET}"
}

function distribute_kube_configs_to_controllers(){
    local CONTROLLER_HOSTNAME=$1
    echo -e "${GREEN}Copying kube configs to server...${RESET}"
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no admin.kubeconfig \
        kube-controller-manager.kubeconfig \
        kube-scheduler.kubeconfig \
        "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
}

function generate_and_copy_encryption_config() {
    local CONTROLLER_HOSTNAME=$1
    
    echo -e "${GREEN}Copying encryption config to $CONTROLLER_HOSTNAME...${RESET}"

    # Generate encryption key
    export ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64)

    # Copy to a controller
    envsubst < configs/encryption-config.yaml > encryption-config.yaml
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no encryption-config.yaml "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"
}

# Deploy etcd
function setup_etcd() {
    local CONTROLLER_HOSTNAME=$1

    echo -e "${GREEN}Installing etcd on $CONTROLLER_HOSTNAME...${RESET}"

    # Move files to the server
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no downloads/etcd.tar.gz units/etcd.service "$USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/"

    # Execute etc config
    sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" << EOF
       
        tar -xvf /home/$USERNAME/etcd.tar.gz
        echo "$SUDO_PASSWORD" | sudo -S mv /home/$USERNAME/etcd-v$ETCD_V-linux-$SYSTEM_ARCH/etcd* /usr/local/bin/

        echo "$SUDO_PASSWORD" | sudo -S mkdir -p /etc/etcd /var/lib/etcd
        echo "$SUDO_PASSWORD" | sudo -S chmod 700 /var/lib/etcd

        echo "$SUDO_PASSWORD" | sudo -S cp /home/$USERNAME/ca.crt /home/$USERNAME/kube-api-server.key /home/$USERNAME/kube-api-server.crt /etc/etcd/

        echo "$SUDO_PASSWORD" | sudo -S mv /home/$USERNAME/etcd.service /etc/systemd/system/

        echo "$SUDO_PASSWORD" | sudo -S systemctl daemon-reload
        echo "$SUDO_PASSWORD" | sudo -S systemctl enable etcd
        #echo "$SUDO_PASSWORD" | sudo -S systemctl start etcd

        #etcdctl member list
EOF
}

function setup_kubernetes_master() {
    local CONTROLLER_HOSTNAME=$1

echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
    downloads/kube-apiserver \
    downloads/kube-controller-manager \
    downloads/kube-scheduler \
    downloads/kubectl \
    units/kube-apiserver.service \
    units/kube-controller-manager.service \
    units/kube-scheduler.service \
    configs/kube-scheduler.yaml \
    configs/kube-apiserver-to-kubelet.yaml \
    $USERNAME@$CONTROLLER_HOSTNAME:/home/$USERNAME/


sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$CONTROLLER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
   
    mkdir -p /etc/kubernetes/config /var/lib/kubernetes
    chmod +x /home/$USERNAME/kube-apiserver /home/$USERNAME/kube-controller-manager /home/$USERNAME/kube-scheduler /home/$USERNAME/kubectl

    
    mv /home/$USERNAME/kube-apiserver /home/$USERNAME/kube-controller-manager /home/$USERNAME/kube-scheduler /home/$USERNAME/kubectl /usr/local/bin/
    mv /home/$USERNAME/ca.crt /home/$USERNAME/ca.key /home/$USERNAME/kube-api-server.key /home/$USERNAME/kube-api-server.crt /home/$USERNAME/service-accounts.key /home/$USERNAME/service-accounts.crt /home/$USERNAME/encryption-config.yaml /var/lib/kubernetes/

    mv /home/$USERNAME/kube-apiserver.service /etc/systemd/system/
    mv /home/$USERNAME/kube-controller-manager.service /etc/systemd/system/
    mv /home/$USERNAME/kube-scheduler.service /etc/systemd/system/

    mv /home/$USERNAME/kube-controller-manager.kubeconfig /var/lib/kubernetes/
    mv /home/$USERNAME/kube-scheduler.kubeconfig /var/lib/kubernetes/

    mv /home/$USERNAME/kube-scheduler.yaml /etc/kubernetes/config/

    systemctl daemon-reload
    systemctl enable kube-apiserver kube-controller-manager kube-scheduler
    systemctl start kube-apiserver kube-controller-manager kube-scheduler

    sleep 10
    
    kubectl apply -f /home/$USERNAME/kube-apiserver-to-kubelet.yaml --kubeconfig /home/$USERNAME/admin.kubeconfig
'"

# Verify the cluster status
curl -k --cacert ca.crt $SERVER_URL

}

# Function to process information from machines.txt and execute tasks on each node
function prepare_nodes() {
    local WORKER_HOSTNAME=$1
    local SUBNET=$2


    # Adapt the configurations
    sed "s|SUBNET|$SUBNET|g" configs/10-bridge.conf > 10-bridge.conf 
    sed "s|SUBNET|$SUBNET|g" configs/kubelet-config.yaml > kubelet-config.yaml 

    # Copy configurations to the remote node
    echo "$SUDO_PASSWORD" | sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no 10-bridge.conf kubelet-config.yaml $USERNAME@$WORKER_HOSTNAME:/home/$USERNAME/ 

    # Copy additional files
    sshpass -p "$SUDO_PASSWORD" scp -o StrictHostKeyChecking=no \
        downloads/runc \
        downloads/crictl.tar.gz \
        downloads/cni-plugins.tgz \
        downloads/containerd.tar.gz \
        downloads/kubectl \
        downloads/kubelet \
        downloads/kube-proxy \
        configs/99-loopback.conf \
        configs/containerd-config.toml \
        configs/kubelet-config.yaml \
        configs/kube-proxy-config.yaml \
        units/containerd.service \
        units/kubelet.service \
        units/kube-proxy.service \
        $USERNAME@$WORKER_HOSTNAME:/home/$USERNAME/ 

    # SSH into the node and run commands with superuser privileges
    sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no -n "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c 'apt-get update && apt-get -y install socat conntrack ipset && swapoff -a && swapon --show'"
}

function setup_nodes() {
    local WORKER_HOSTNAME=$1
   
    sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no -n "$USERNAME@$WORKER_HOSTNAME" "echo '$SUDO_PASSWORD' | sudo -S bash -c '
    mkdir -p /etc/cni/net.d /opt/cni/bin /var/lib/kubelet /var/lib/kube-proxy /var/lib/kubernetes /var/run/kubernetes &&

    mkdir -p containerd && 
    tar -xvf crictl.tar.gz && 
    tar -xvf containerd.tar.gz -C containerd && 
    tar -xvf cni-plugins.tgz -C /opt/cni/bin/ && 
    chmod +x crictl kubectl kube-proxy kubelet runc && 
    mv crictl kubectl kube-proxy kubelet runc /usr/local/bin/ && 
    mv containerd/bin/* /bin/ &&

    mv 10-bridge.conf 99-loopback.conf /etc/cni/net.d/ &&

    mkdir -p /etc/containerd/ && 
    mv containerd-config.toml /etc/containerd/config.toml && 
    mv containerd.service /etc/systemd/system/ &&

    mv kubelet-config.yaml /var/lib/kubelet/ && 
    mv kubelet.service /etc/systemd/system/ &&

    mv kube-proxy-config.yaml /var/lib/kube-proxy/ && 
    mv kube-proxy.service /etc/systemd/system/ &&

    systemctl daemon-reload && 
    systemctl enable containerd kubelet kube-proxy && 
    systemctl start containerd kubelet kube-proxy'"
}

function configure_kubectl() {
    
  kubectl config set-cluster kubernetes-the-hard-way \
    --certificate-authority=ca.crt \
    --embed-certs=true \
    --server=$SERVER_URL

  kubectl config set-credentials admin \
    --client-certificate=admin.crt \
    --client-key=admin.key

  kubectl config set-context kubernetes-the-hard-way \
    --cluster=kubernetes-the-hard-way \
    --user=admin

  kubectl config use-context kubernetes-the-hard-way

}

function check_cluster() {
  echo -e "${CYAN}============================${RESET}"
  curl -k --cacert ca.crt $SERVER_URL
  echo
  echo -e "${CYAN}============================${RESET}"
  echo
  kubectl version
  echo
  echo -e "${CYAN}============================${RESET}"
  echo
  kubectl get nodes
  echo
  echo -e "${CYAN}============================${RESET}"
  echo
}

#legacy function; Idk what to do in case of LB
function setup_routes() {
  SERVER_IP=$(grep controller-0 machines.txt | cut -d " " -f 2)

  NODE_IPS=()
  NODE_SUBNETS=()
  i=0

  while read -r ROLE IP FQDN HOSTNAME SUBNET; do
    if [[ $ROLE == *worker* ]]; then
      NODE_IPS+=("$IP")
      NODE_SUBNETS+=("$SUBNET")
      ((i++))
    fi
  done < machines.txt

  # Подключаемся к серверу и добавляем маршруты
  echo "Adding routes on server"
  for i in "${!NODE_IPS[@]}"; do
    echo "On server, adding route to ${NODE_SUBNETS[$i]} via ${NODE_IPS[$i]}"
    sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$SERVER_IP" "echo '$SUDO_PASSWORD' | sudo -S ip route add ${NODE_SUBNETS[$i]} via ${NODE_IPS[$i]} && ip route"
  done

  # Добавляем маршруты для каждого узла, исключая саму себя
  for i in "${!NODE_IPS[@]}"; do
    NODE_IP=${NODE_IPS[$i]}
    NODE_SUBNET=${NODE_SUBNETS[$i]}

    for j in "${!NODE_IPS[@]}"; do
      if [[ $i -ne $j ]]; then
        TARGET_IP=${NODE_IPS[$j]}
        TARGET_SUBNET=${NODE_SUBNETS[$j]}
        echo "On node-$i, adding route to ${TARGET_SUBNET} via ${TARGET_IP}"
        sshpass -p "$SUDO_PASSWORD" ssh -o StrictHostKeyChecking=no "$USERNAME@$NODE_IP" "echo '$SUDO_PASSWORD' | sudo -S ip route add ${TARGET_SUBNET} via ${TARGET_IP} && ip route"
      fi
    done
  done
}

function pre_process_controllers() {
    # Use grep to filter lines containing 'controller' and loop through each filtered line
    mapfile -t CONTROLLERS < <(grep 'controller' "$MACHINES_FILE")
    for LINE in "${CONTROLLERS[@]}"; do
        IFS=" " read -r ROLE IP FQDN HOSTNAME SUBNET <<< "$LINE"
        # Create variables based on the extracted values
        CONTROLLER_HOSTNAME=$HOSTNAME
        CONTROLLER_IP=$IP
        CONTROLLER_FQDN=$FQDN
        CONTROLLER_ROLE=$ROLE
        CONTROLLER_SUBNET=$SUBNET

        adding_remote_nodes_to_hosts_file "$CONTROLLER_IP" "$CONTROLLER_FQDN" "$CONTROLLER_HOSTNAME" 
        update_remote_hosts_file "$CONTROLLER_FQDN" "$CONTROLLER_HOSTNAME" 

        done
}

function pre_process_workers() {
    # Use grep to filter lines containing 'worker' and loop through each filtered line
    mapfile -t WORKERS < <(grep 'worker' "$MACHINES_FILE")
    for LINE in "${WORKERS[@]}"; do
        IFS=" " read -r ROLE IP FQDN HOSTNAME SUBNET <<< "$LINE"
        # Create variables based on the extracted values
        WORKER_HOSTNAME=$HOSTNAME
        WORKER_IP=$IP
        WORKER_FQDN=$FQDN
        WORKER_ROLE=$ROLE
        WORKER_SUBNET=$SUBNET

        adding_remote_nodes_to_hosts_file "$WORKER_IP" "$WORKER_FQDN" "$WORKER_HOSTNAME" 
        update_remote_hosts_file "$WORKER_FQDN" "$WORKER_HOSTNAME" 
        add_worker_to_ca_conf "$WORKER_HOSTNAME" 
                
        done    
}        
# Function to process and extract information for controllers from machines.txt
function process_controllers() {
    # Use grep to filter lines containing 'controller' and loop through each filtered line
    mapfile -t CONTROLLERS < <(grep 'controller' "$MACHINES_FILE")
        for LINE in "${CONTROLLERS[@]}"; do
        IFS=" " read -r ROLE IP FQDN HOSTNAME SUBNET <<< "$LINE"
        # Create variables based on the extracted values
        CONTROLLER_HOSTNAME=$HOSTNAME
        CONTROLLER_IP=$IP
        CONTROLLER_FQDN=$FQDN
        CONTROLLER_ROLE=$ROLE
        CONTROLLER_SUBNET=$SUBNET


        distribute_ssh_keys "$CONTROLLER_FQDN"  
        distribute_kube_configs_to_controllers "$CONTROLLER_HOSTNAME" 
        generate_and_copy_encryption_config "$CONTROLLER_HOSTNAME" 
        distribute_controller_certs "$CONTROLLER_HOSTNAME" 
        setup_etcd "$CONTROLLER_HOSTNAME" 
        setup_kubernetes_master "$CONTROLLER_HOSTNAME" 
    done
}

# Function to process and extract information for workers from machines.txt
function process_workers() {
    # Use grep to filter lines containing 'worker' and loop through each filtered line
    mapfile -t WORKERS < <(grep 'worker' "$MACHINES_FILE")
        for LINE in "${WORKERS[@]}"; do
        IFS=" " read -r ROLE IP FQDN HOSTNAME SUBNET <<< "$LINE"
        # Create variables based on the extracted values
        WORKER_HOSTNAME=$HOSTNAME
        WORKER_IP=$IP
        WORKER_FQDN=$FQDN
        WORKER_ROLE=$ROLE
        WORKER_SUBNET=$SUBNET

        distribute_ssh_keys "$WORKER_FQDN" 
        generate_worker_certificates "$WORKER_HOSTNAME" "$WORKER_ROLE" 
        distribute_worker_certs "$WORKER_HOSTNAME" 
        generate_k8s_worker_configs "$WORKER_HOSTNAME" 
        distribute_kube_configs_to_workers "$WORKER_HOSTNAME" 
        prepare_nodes "$WORKER_HOSTNAME" "$WORKER_SUBNET" 
        setup_nodes "$WORKER_HOSTNAME" 
    done
}

# Main script execution
display_welcome
get_credentials
check_os
get_architecture
check_required_packages
prompt_for_versions
validate_downloads_file
download_files
install_kubectl 
check_machines_file 
echo -e "Deploying the cluster..."
echo -e "Might take some time..."
add_controllers_to_ca_conf 
generate_ssh_keys 

#preprocess 
echo -e "Preprocessing controller(s)..."
pre_process_controllers 
echo -e "Preprocessing workers(s)..."
pre_process_workers 

echo -e "Creating CA certificate and key pair..."
create_ca_crt_and_key 
echo -e "Generating the rest of the SSL pairs..."
generate_common_certs 
echo -e "Creating k8s controller config(s)..."
generate_k8s_controller_configs 

# Process controllers and workers separetely
echo -e "Processing controller(s)..."
echo "ROLE: $ROLE, IP: $IP, FQDN: $FQDN, HOSTNAME: $HOSTNAME"
process_controllers 
echo -e "Processing workers(s)..."
process_workers 

# Main script execution continue
echo -e "Configuring kubectl..."
configure_kubectl 
echo -e "Setting up routes..."
setup_routes 
echo -e "Sleeping 15 seconds..."
sleep 15 
check_cluster
echo -e "${GREEN}Deploy complete${RESET} 🐗"
