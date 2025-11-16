#!/usr/bin/env bash
# ubuntu24-dev-setup.sh
# Idempotent helper to set up a developer environment on Ubuntu 24.04
# Prompts the user to install Docker Engine, containerd, or neither (default: neither)
# Also installs common dev tools: Python/pyenv/pipx, nvm/node, go, kubectl, helm, kind, misc tools

set -euo pipefail

SCRIPT_NAME="ubuntu24-dev-setup"

# Defaults
INSTALL_CHOICE="none"   # docker|containerd|none
ASSUME_YES=0

log() { echo "[${SCRIPT_NAME}] $*"; }

usage() {
  cat <<EOF
Usage: sudo ./ubuntu24-dev-setup.sh [--install docker|containerd|none] [-y|--yes] [--help]

Options:
  --install <docker|containerd|none>  Choose runtime to install. If omitted the script will prompt interactively.
  -y, --yes                          Non-interactive: assume yes for prompts.
  --help                             Show this help and exit.

This script is idempotent and targets Ubuntu 24.04. It installs common development tooling and optionally
Docker Engine or containerd as the container runtime.
EOF
}

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --install)
      shift
      if [[ $# -eq 0 ]]; then
        echo "ERROR: --install requires an argument" >&2; exit 2
      fi
      case "$1" in
        docker|containerd|none)
          INSTALL_CHOICE="$1"; shift;;
        *) echo "ERROR: --install value must be 'docker', 'containerd', or 'none'" >&2; exit 2;;
      esac
      ;;
    -y|--yes)
      ASSUME_YES=1; shift;;
    --help)
      usage; exit 0;;
    *) echo "Unknown argument: $1" >&2; usage; exit 2;;
  esac
done

ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root: sudo $0 $*" >&2
    exit 1
  fi
}

prompt_choice() {
  if [[ $ASSUME_YES -eq 1 ]]; then
    log "Non-interactive mode: using --install=${INSTALL_CHOICE:-none}"
    return
  fi

  if [[ "$INSTALL_CHOICE" == "none" ]]; then
    echo "Choose container runtime to install on this machine:";
    echo "  1) Docker Engine (canonical Docker)
  2) containerd only (no Docker CLI)
  3) None (skip container runtime)"
    read -rp "Enter choice [1-3] (default 3): " choice
    choice=${choice:-3}
    case "$choice" in
      1) INSTALL_CHOICE=docker;;
      2) INSTALL_CHOICE=containerd;;
      3) INSTALL_CHOICE=none;;
      *) echo "Invalid choice"; exit 2;;
    esac
  else
    log "Using runtime choice from arguments: ${INSTALL_CHOICE}"
  fi
}

update_and_install_base() {
  log "Updating apt and installing base packages..."
  apt update && apt upgrade -y
  apt install -y build-essential curl file git ca-certificates lsb-release wget gnupg2 software-properties-common
  apt install -y htop tmux tree unzip zsh sqlite3 openssl
}

install_docker_engine() {
  log "Installing Docker Engine (Docker CE)..."
  # Install per Docker instructions
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    > /etc/apt/sources.list.d/docker.list
  apt update
  apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
  systemctl enable --now containerd || true
  systemctl enable --now docker || true
  # Add current user to docker group (preserve $SUDO_USER if present)
  user_to_modify=${SUDO_USER:-$LOGNAME}
  if ! id -nG "$user_to_modify" | grep -qw docker; then
    usermod -aG docker "$user_to_modify" && log "Added $user_to_modify to docker group; relogin required."
  else
    log "User $user_to_modify already in docker group"
  fi
}

install_containerd_only() {
  log "Installing containerd (no Docker Engine)..."
  apt update
  apt install -y containerd
  systemctl enable --now containerd || true
  # configure default containerd config if missing (minimal safe defaults)
  if [[ ! -f /etc/containerd/config.toml ]]; then
    log "Generating default /etc/containerd/config.toml"
    containerd config default > /etc/containerd/config.toml || true
    systemctl restart containerd || true
  fi
}

install_python_pyenv_pipx() {
  log "Installing pyenv and pipx"
  apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev
  if [[ ! -d "$HOME/.pyenv" ]]; then
    su - "$SUDO_USER" -c "curl https://pyenv.run | bash" || true
    log "pyenv installed for user $SUDO_USER"
  else
    log "pyenv already installed"
  fi
  apt install -y python3-pip python3-venv || true
  su - "$SUDO_USER" -c "python3 -m pip install --user pipx || true"
}

install_nvm_node() {
  log "Installing nvm and LTS Node.js for user $SUDO_USER"
  su - "$SUDO_USER" -c 'bash -c "curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.4/install.sh | bash"'
  su - "$SUDO_USER" -c 'bash -lc "export NVM_DIR=\"$HOME/.nvm\"; [ -s \"$NVM_DIR/nvm.sh\" ] && . \"$NVM_DIR/nvm.sh\"; nvm install --lts || true; nvm use --lts || true; npm install -g npm@latest || true"'
}

install_go() {
  log "Installing Go via apt"
  if command -v go >/dev/null 2>&1; then
    log "go already installed: $(go version)"
    return
  fi
  apt install -y golang
}

install_k8s_tools() {
  log "Installing kubectl, helm, kind"
  # kubectl
  if ! command -v kubectl >/dev/null 2>&1; then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    mv kubectl /usr/local/bin/
  else
    log "kubectl already installed"
  fi
  # helm
  if ! command -v helm >/dev/null 2>&1; then
    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
  else
    log "helm already installed"
  fi
  # kind
  if ! command -v kind >/dev/null 2>&1; then
    curl -Lo ./kind https://kind.sigs.k8s.io/dl/v0.20.0/kind-linux-amd64
    chmod +x kind
    mv kind /usr/local/bin/
  else
    log "kind already installed"
  fi
}

install_misc_tools() {
  log "Installing misc CLI tools: gh, shellcheck, docker-compose plugin"
  apt install -y gh shellcheck docker-compose-plugin || true
}

post_install_notes() {
  cat <<EOF

Setup complete (or mostly complete). Next steps / verification:

- Close all shells and re-open sessions to refresh group membership (docker group).
- Verify docker (if installed): docker run --rm hello-world
- Verify containerd: containerd --version
- Verify kubectl: kubectl version --client
- Verify helm: helm version
- Verify kind: kind --version
- Verify node and npm: node --version && npm --version
- Verify python: python3 --version; try 'pyenv install 3.11.8' as the non-root user

EOF
}

main() {
  ensure_root
  prompt_choice
  update_and_install_base

  case "$INSTALL_CHOICE" in
    docker) install_docker_engine;;
    containerd) install_containerd_only;;
    none) log "Skipping container runtime installation as requested";;
    *) echo "Internal error: unknown INSTALL_CHOICE=$INSTALL_CHOICE" >&2; exit 2;;
  esac

  install_python_pyenv_pipx
  install_nvm_node
  install_go
  install_k8s_tools
  install_misc_tools
  post_install_notes
}

# small helper to ensure script is run as root
ensure_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "ERROR: please run this script as root (use sudo)." >&2
    exit 1
  fi
}

main "$@"
