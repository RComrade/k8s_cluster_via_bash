# K8S Cluster Deployment via Bash

This project is under development as part of my personal Bash and Kubernetes studies.

### Current Stage
The current stage allows deploying a Kubernetes (K8s) cluster with multiple worker nodes and more than one controller. However, after deployment, any additional controller should be joined to the master via `kubeadm`, which is not automatically installed with this script.

### Prerequisites
To run this script, you need several (at least 3) Debian-based hosts (either VMs or physical machines):
- 1 or more for a controller
- 1 or more for a worker
- 1 as a jumppad (a host used to generate initial K8s configs, certificates, etc., for further distribution across the hosts)

#### Requirements for all hosts:
- The same user credentials with superuser rights on all machines
- All hosts must have a network connection between each other
- You need to know the hostname for each host 

### Steps to Deploy

1. Clone the repository to the jumppad host:
    ```bash
    git clone https://github.com/RComrade/k8s_cluster_via_bash.git
    ```

2. Navigate to the project folder:
    ```bash
    cd k8s_cluster_via_bash
    ```

3. Run the deployment script:
    ```bash
    bash deploy.sh
    ```

### What Happens Next?

- The script will automatically check for the latest K8s version
- The rest of the software versions are hardcoded at the beginning of the script
- You'll be prompted to confirm the necessary versions
- After the checks are passed, you'll be asked for `machines.txt` — an inventory file
 

Here's an example of its format:

    ```
    controller-0 192.168.1.10 server-0.kubernetes.local server-0
    controller-1 192.168.1.3 server.kubernetes.local server
    worker-0 192.168.1.11 node-0.kubernetes.local node-0 10.200.0.0/24
    worker-1 192.168.1.13 node-1.kubernetes.local node-1 10.200.1.0/24
    worker-2 192.168.1.8 metalb.kubernetes.local metalb 10.200.2.0/24
    ```

   The columns are:
   - **Role**: Used for internal script logic
   - **IPv4**: The real IPv4 address of a host to be used in the cluster
   - **FQDN**: The fully qualified domain name of the host (e.g., `server-0.kubernetes.local`). It can be customized but has been tested with `kubernetes.local` domain only
   - **Hostname**: The actual hostname of the host, set during OS setup or initial configuration
   - **Network** (for workers only): This is required for starting containers within the worker; virtual network information (e.g., `10.200.0.0/24`)

You will be asked to input the `machines.txt` details or provide the file manually in the project folder.

### Summary

Once you've answered the initial prompts, the script should handle the rest of the setup

Feel free to reach out for feedback, questions, or bug reports

**Telegram:** [@nvyatkin9154](https://t.me/nvyatkin9154)
