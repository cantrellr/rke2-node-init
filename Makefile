# Utility helpers for project maintenance.
#
# Usage:
#   make token [TOKEN_SIZE=24]
#
# TOKEN_SIZE controls the number of random bytes (default: 12) used when
# generating the base64 token. The resulting token is echoed to stdout and
# persisted at /etc/rancher/rke2/token.d/bootstrap.token.

export SHELL := /bin/bash
export TOKEN_SIZE ?= 32
export TOKEN_IMAGE_NAME ?=
export BOOT_ISO_YAML_DIR ?= configs/cotpa-k802-cluster/nodes
export BOOT_ISO_OUTPUT_DIR ?= configs/cotpa-k802-cluster/boot-isos
export BOOT_ISO_MANIFEST ?= ${BOOT_ISO_OUTPUT_DIR}/manifest.tsv

.PHONY: token sh kubeconfig boot-isos boot-isos-clean ipam-install ipam-run ipam-test ipam-import
## Generate a reusable base64 token and persist it at canonical host path.
token:
	@set -euo pipefail; \
		TOKEN_FILE="/etc/rancher/rke2/token.d/bootstrap.token"; \
		TOKEN_TMP="$${TMPDIR:-/tmp}/rke2-bootstrap-token.$$$$"; \
		TOKEN="$$(openssl rand -base64 ${TOKEN_SIZE})"; \
		printf '%s\n' "$${TOKEN}" > "$${TOKEN_TMP}"; \
		chmod 600 "$${TOKEN_TMP}"; \
		sudo install -d -m 700 "$$(dirname "${TOKEN_FILE}")"; \
		sudo install -m 600 "$${TOKEN_TMP}" "${TOKEN_FILE}"; \
		rm -f "$${TOKEN_TMP}"; \
		echo "     Token: $${TOKEN}"; \
		echo "Token File: ${TOKEN_FILE}";

## Mark all Bash scripts in the repository root as executable.
sh:
	@set -euo pipefail; \
		shopt -s nullglob; \
		chmod a+x *.sh

## Install kubectl and copy the RKE2 kubeconfig for the current user.
kubeconfig:
	@set -euo pipefail; \
		mkdir -p $$HOME/.kube; \
		sudo cp /etc/rancher/rke2/rke2.yaml $$HOME/.kube/config; \
		sudo install -o root -g root -m 0755 /var/lib/rancher/rke2/bin/kubectl /usr/local/bin/kubectl; \
		sudo chown "$$(id -u):$$(id -g)" $$HOME/.kube/config; \
		command -v kubectl; \
		ls -l /usr/local/bin/kubectl; \
		kubectl get node -o wide

## Build per-node boot ISOs from YAML files in a folder (metadata.name.iso).
boot-isos:
	@set -euo pipefail; \
		bash scripts/build-boot-isos.sh \
		  --yaml-dir "${BOOT_ISO_YAML_DIR}" \
		  --output-dir "${BOOT_ISO_OUTPUT_DIR}" \
		  --manifest "${BOOT_ISO_MANIFEST}"

## Remove generated boot ISO artifacts.
boot-isos-clean:
	@set -euo pipefail; \
		rm -rf "${BOOT_ISO_OUTPUT_DIR}"

## Install the IPAM web app and development dependencies.
ipam-install:
	@set -euo pipefail; \
		python -m pip install --upgrade pip; \
		python -m pip install -e ./apps/ipam[dev]

## Run the internal IPAM web application locally.
ipam-run:
	@set -euo pipefail; \
		PYTHONPATH=apps/ipam/src python -m uvicorn ipam.main:app --host 127.0.0.1 --port 8091 --reload

## Run the IPAM application test suite.
ipam-test:
	@set -euo pipefail; \
		PYTHONPATH=apps/ipam/src python -m pytest apps/ipam/tests

## Import an Excel workbook into the IPAM database.
ipam-import:
	@set -euo pipefail; \
		test -n "${WORKBOOK:-}" || { echo "Set WORKBOOK=/absolute/path/to/workbook.xlsx"; exit 1; }; \
		PYTHONPATH=apps/ipam/src python -m ipam.cli import-workbook "${WORKBOOK}"
