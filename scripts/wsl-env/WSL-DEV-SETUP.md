WSL Developer Environment Setup

This script helps set up a Docker-in-WSL development environment supporting two common stacks:

- Python + Node
- Go + Kubernetes (kubectl/helm/kind)

Files
- `wsl-dev-setup.sh` - idempotent bash script to install runtime/tooling inside Ubuntu WSL2.

Quick start
1. Open your WSL Ubuntu distro (Windows Terminal -> Ubuntu) or open a Remote-WSL window in VS Code.
2. Make the script executable and run it:

```bash
chmod +x scripts/wsl-dev-setup.sh
./scripts/wsl-dev-setup.sh
```

What it installs
- System: build-essential, curl, wget, git, ca-certificates, gnupg, htop, tmux, tree, unzip, zsh
- Docker Engine (containerd + docker-ce) inside WSL
- Python helpers: `pyenv` and `pipx`
- Node: `nvm` and latest LTS Node.js
- Go (via apt)
- Kubernetes tools: `kubectl`, `helm`, `kind`
- Misc: `gh` (GitHub CLI), `shellcheck`, `docker compose` plugin

Notes and caveats
- The script installs Docker Engine inside WSL. If you prefer Docker Desktop integration with WSL2, it's recommended to use Docker Desktop on Windows and enable WSL integration instead of running Docker Engine inside WSL. If you choose Docker Desktop, you can skip or remove the Docker Engine portion of the script.
- After being added to the `docker` group, you must log out and back in (or restart WSL) for group membership to take effect.
- The script uses apt for installing some packages (e.g., Go). If you need a specific Go version, install it manually from the official tarball.
- `pyenv` installs to `~/.pyenv`. After running the script, add the recommended `pyenv` init lines to your shell RC (`~/.bashrc` or `~/.zshrc`) if not already present.

Verification
Run these commands in a fresh WSL shell after the script finishes to verify:

```bash
docker run --rm hello-world
kubectl version --client
helm version
kind --version
node --version && npm --version
python3 --version
gh auth status
```

Local certificate testing
-------------------------

If you need to generate a test Root / Subordinate CA for local RKE2 testing, use the repository's certs scripts and Makefile targets rather than committing keys to git:

```bash
# From the repo root
make certs-root-ca
make certs-sub-ca INPUT=certs/examples/rke2clusterCA-example.yaml
```

Customization
Edit `scripts/wsl-dev-setup.sh` to pin specific versions or to remove pieces you don't need.

Support
If you have issues, capture the failing command, its output, and your WSL distro / Windows build number and open an issue.
