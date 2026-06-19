#!/usr/bin/env bash
# wsl-dev-setup.sh
# Idempotent helper to set up a developer environment inside Ubuntu WSL2
# Stacks: Python + Node  and  Go + Kubernetes

set -euo pipefail

# Configuration - change versions here if needed
NVM_VERSION="v0.39.4"
PYENV_ROOT="$HOME/.pyenv"
# Keep the pyenv init snippet literal (do not evaluate $(pyenv init -) at script parse time)
PYENV_INIT_SCRIPT='export PATH="$PYENV_ROOT/bin:$PATH"\neval "$(pyenv init -)"'
RUSTUP_INIT_URL="https://sh.rustup.rs"
KIND_VERSION="v0.20.0"

log() { echo "[wsl-dev-setup] $*"; }

ensure_sudo() {
  if [ "$EUID" -ne 0 ]; then
    log "Some steps need sudo. You may be prompted for your password.";
  fi
}

update_and_install_base() {
  log "Updating APT and installing base packages..."
  sudo apt update && sudo apt upgrade -y
  sudo apt install -y build-essential curl file git ca-certificates lsb-release wget gnupg2 software-properties-common
  sudo apt install -y htop tmux tree unzip zsh sqlite3 openssl
}

install_docker_engine() {
  log "Installing Docker Engine in WSL..."
  # Follow canonical Docker Engine install steps for Ubuntu
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
  echo \
    "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt update
  sudo apt install -y docker-ce docker-ce-cli containerd.io
  # Enable and start containerd and docker
  sudo systemctl enable --now containerd || true
  sudo systemctl enable --now docker || true || true

  # Add user to docker group
  if ! groups "$USER" | grep -qw docker; then
    sudo usermod -aG docker "$USER" && log "Added $USER to docker group. Re-login required for group membership to apply."
  else
    log "User already in docker group"
  fi
}

install_python_pyenv_pipx() {
  log "Installing pyenv and pipx (Python toolchain)"
  # pyenv dependencies
  sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev wget llvm libncurses5-dev libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev
  # install pyenv
  if [ ! -d "$PYENV_ROOT" ]; then
    curl https://pyenv.run | bash
    log "pyenv installed to $PYENV_ROOT"
  else
    log "pyenv already installed"
  fi

  # Ensure pyenv paths are in this shell (best-effort)
  export PATH="$PYENV_ROOT/bin:$PATH"
  if command -v pyenv >/dev/null 2>&1; then
    eval "$(pyenv init -)" || true
  fi

  # pipx
  # Ensure pip is available
  sudo apt install -y python3-pip python3-venv || true
  # Try user install first; on some distros PEP 668 blocks this, so fall back to apt
  python3 -m pip install --user pipx || true
  if ! command -v pipx >/dev/null 2>&1; then
    log "pipx not available via pip; trying apt package 'pipx' as fallback"
    sudo apt update || true
    sudo apt install -y pipx || true
  fi
  # Ensure pipx path is available for this session
  export PATH="$HOME/.local/bin:$PATH"
  python3 -m pipx ensurepath || true
}

ensure_shell_rc() {
  # Add pyenv and nvm initialization to shell rc files if not present
  local bashrc="$HOME/.bashrc"
  local zshrc="$HOME/.zshrc"

  # pyenv init snippet
  local pyenv_snippet='export PYENV_ROOT="$HOME/.pyenv"\n[[ -d $PYENV_ROOT/bin ]] && export PATH="$PYENV_ROOT/bin:$PATH"\neval "$(pyenv init -)"\neval "$(pyenv virtualenv-init -)"'

  # nvm snippet
  local nvm_snippet='export NVM_DIR="$HOME/.nvm"\n[ -s "\$NVM_DIR/nvm.sh" ] && . "\$NVM_DIR/nvm.sh"'

  # Append to bashrc if missing
  if [ -f "$bashrc" ]; then
    if ! grep -q "pyenv init" "$bashrc" 2>/dev/null; then
      printf "\n# pyenv init (added by wsl-dev-setup)\n%s\n" "$pyenv_snippet" >> "$bashrc"
      log "Appended pyenv init to $bashrc"
    fi
    if ! grep -q "nvm.sh" "$bashrc" 2>/dev/null; then
      printf "\n# nvm init (added by wsl-dev-setup)\n%s\n" "$nvm_snippet" >> "$bashrc"
      log "Appended nvm init to $bashrc"
    fi
  fi

  # Append to zshrc if present
  if [ -f "$zshrc" ]; then
    if ! grep -q "pyenv init" "$zshrc" 2>/dev/null; then
      printf "\n# pyenv init (added by wsl-dev-setup)\n%s\n" "$pyenv_snippet" >> "$zshrc"
      log "Appended pyenv init to $zshrc"
    fi
    if ! grep -q "nvm.sh" "$zshrc" 2>/dev/null; then
      printf "\n# nvm init (added by wsl-dev-setup)\n%s\n" "$nvm_snippet" >> "$zshrc"
      log "Appended nvm init to $zshrc"
    fi
  fi
}

install_nvm_node() {
  log "Installing nvm and latest LTS Node.js"
  if [ ! -d "$HOME/.nvm" ]; then
    curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/$NVM_VERSION/install.sh | bash
  else
    log "nvm already installed"
  fi
  # Load nvm for this shell
  export NVM_DIR="$HOME/.nvm"
  # Run nvm commands in a fresh bash shell to avoid 'set -u' / nounset errors from the nvm script
  bash -lc "export NVM_DIR=\"$HOME/.nvm\"; [ -s \"\$NVM_DIR/nvm.sh\" ] && . \"\$NVM_DIR/nvm.sh\"; nvm install --lts || true; nvm use --lts || true; npm install -g npm@latest || true"
}

install_go() {
  log "Installing Go (latest stable)"
  # Use apt as a simple path, but prefer downloading latest if apt is old
  if command -v go >/dev/null 2>&1; then
    log "go already installed: $(go version)"
    return
  fi
  GO_LATEST_URL="https://go.dev/dl/"
  # Download latest stable archive parsing index.html is complex; use apt for simplicity
  sudo apt install -y golang
}

install_k8s_tools() {
  log "Installing kubectl, helm, kind"
  # kubectl
  if ! command -v kubectl >/dev/null 2>&1; then
    curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
    chmod +x kubectl
    sudo mv kubectl /usr/local/bin/
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
    curl -Lo ./kind https://kind.sigs.k8s.io/dl/${KIND_VERSION}/kind-linux-amd64
    chmod +x kind
    sudo mv kind /usr/local/bin/
  else
    log "kind already installed"
  fi
}

install_misc_tools() {
  log "Installing misc CLI tools: gh, docker-compose (plugin), shellcheck"
  # GitHub CLI
  if ! command -v gh >/dev/null 2>&1; then
    sudo apt install -y gh || true
  fi
  # shellcheck
  if ! command -v shellcheck >/dev/null 2>&1; then
    sudo apt install -y shellcheck || true
  fi
  # docker compose plugin: newer Docker uses compose as plugin
  if ! docker compose version >/dev/null 2>&1; then
    sudo apt install -y docker-compose-plugin || true
  fi
}

post_install_notes() {
  cat <<EOF

Setup complete (or mostly complete). Next steps / verification:

- Close all WSL terminals and start a new session to refresh group membership (docker group).
- Verify docker: docker run --rm hello-world
- Verify kubectl: kubectl version --client
- Verify helm: helm version
- Verify kind: kind --version
- Verify node and npm: node --version && npm --version
- Verify python: python3 --version; try 'pyenv install 3.11.8' etc.
- If you want Docker Desktop integration with WSL2 instead of running Docker Engine in WSL, uninstall the docker packages installed here and use Docker Desktop with WSL integration enabled.

EOF
}

main() {
  ensure_sudo
  update_and_install_base
  install_docker_engine
  install_python_pyenv_pipx
  install_nvm_node
  install_go
  install_k8s_tools
  install_misc_tools
  post_install_notes
}

main "$@"
