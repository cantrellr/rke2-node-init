# Utility helpers for project maintenance.
#
# Usage:
#   make token [TOKEN_SIZE=24]
#
# TOKEN_SIZE controls the number of random bytes (default: 12) used when
# generating the base64 token. The resulting token is echoed to stdout and
# persisted under outputs/generated-token/ with the invocation timestamp.

export SHELL := /bin/bash
export TOKEN_SIZE ?= 32
export TOKEN_OUTPUT_DIR := outputs/generated-token
export TOKEN_TIMESTAMP := $(shell date +%Y%m%d-%H%M%S)
export TOKEN_FILE := ${TOKEN_OUTPUT_DIR}/token-${TOKEN_TIMESTAMP}.txt

.PHONY: token sh kubeconfig certs-root-ca certs-sub-ca certs-verify
 .PHONY: certs-assert
## Generate a reusable base64 token and persist it for later use.
token:
	@set -euo pipefail; \
		install -d -m 700 ${TOKEN_OUTPUT_DIR}; \
		TOKEN="$$(openssl rand -base64 ${TOKEN_SIZE})"; \
		printf '%s\n' "$${TOKEN}" | tee "${TOKEN_FILE}"; \
		chmod 600 "${TOKEN_FILE}"; \
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

## Certificates targets - delegate to certs/Makefile
certs-root-ca:
	@set -euo pipefail; \
		OUTDIR=$${OUTDIR:-outputs/certs}; \
		TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
		mkdir -p "$$OUTDIR"; \
		./certs/scripts/generate-root-ca.sh --out-dir "$$OUTDIR/root-$$TIMESTAMP";

certs-sub-ca:
	@set -euo pipefail; \
		# If INPUT not provided interactively prompt when running in a TTY,
		# otherwise print usage and exit (non-interactive CI will fail fast).
		if [ -z "${INPUT-}" ]; then \
			if [ -t 0 ]; then \
				read -r -p "INPUT not provided. Enter path to input YAML: " INPUT; \
				: "${INPUT}"; \
			else \
				echo "Usage: make certs-sub-ca INPUT=path/to/input.yaml"; exit 1; \
			fi; \
		fi; \
		# Verify input file exists
		if [ ! -f "${INPUT}" ]; then \
			echo "ERROR: INPUT file not found: ${INPUT}"; exit 1; \
		fi; \
		OUTDIR=$${OUTDIR:-outputs/certs}; \
		TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
		mkdir -p "$$OUTDIR"; \
		# Optionally forward subordinate key encryption flags from Make invocation
		ENCRYPT_FLAG=""; \
		SUB_PASSFILE_FLAG=""; \
		if [ "${SUB_ENCRYPT-}" = "true" ]; then ENCRYPT_FLAG="--encrypt-sub-key"; fi; \
		if [ -n "${SUB_PASSFILE-}" ]; then SUB_PASSFILE_FLAG="--sub-passfile ${SUB_PASSFILE}"; fi; \
		# Forward optional subordinate pathlen (default 1 so subCA can sign other CAs)
		SUB_PATHLEN_FLAG=""; \
		if [ -z "${SUB_PATHLEN-}" ]; then SUB_PATHLEN=1; fi; \
		if [ -n "${SUB_PATHLEN-}" ]; then SUB_PATHLEN_FLAG="--pathlen ${SUB_PATHLEN}"; fi; \
		# Forward optional root key/cert/pass to enable fully non-interactive runs
		ROOT_KEY_FLAG=""; ROOT_CERT_FLAG=""; ROOT_PASS_FLAG=""; \
		if [ -n "${ROOT_KEY-}" ]; then ROOT_KEY_FLAG="--root-key ${ROOT_KEY}"; fi; \
		if [ -n "${ROOT_CERT-}" ]; then ROOT_CERT_FLAG="--root-cert ${ROOT_CERT}"; fi; \
		if [ -n "${ROOT_PASS-}" ]; then ROOT_PASS_FLAG="--root-passphrase ${ROOT_PASS}"; fi; \
		./certs/scripts/generate-subordinate-ca.sh ${ENCRYPT_FLAG} ${SUB_PASSFILE_FLAG} ${SUB_PATHLEN_FLAG} ${ROOT_KEY_FLAG} ${ROOT_CERT_FLAG} ${ROOT_PASS_FLAG} --input "${INPUT}" --out-dir "$$OUTDIR/subca-$$TIMESTAMP";

## Safer wrapper: validate INPUT and run generation as the invoking user.
## If INSTALL=true, perform privileged install steps (only escalate that step).
certs-sub-ca-safe:
	@set -euo pipefail; \
		if [ -z "${INPUT-}" ]; then \
			if [ -t 0 ]; then \
				read -r -p "INPUT not provided. Enter path to input YAML: " INPUT; \
				: "${INPUT}"; \
			else \
				echo "Usage: make certs-sub-ca-safe INPUT=path/to/input.yaml"; exit 1; \
			fi; \
		fi; \
		if [ ! -f "${INPUT}" ]; then \
			echo "ERROR: INPUT file not found: ${INPUT}"; exit 1; \
		fi; \
		OUTDIR=$${OUTDIR:-outputs/certs}; \
		TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
		mkdir -p "$$OUTDIR"; \
		# Run generation as the current user (no sudo). The script itself should
		# write outputs to OUTDIR/subca-<timestamp>.
		# Default pathlen to 1 so the subordinate CA can sign other CAs unless overridden
		if [ -z "${SUB_PATHLEN-}" ]; then SUB_PATHLEN=1; fi; \
		SUB_PATHLEN_FLAG="--pathlen ${SUB_PATHLEN}"; \
		./certs/scripts/generate-subordinate-ca.sh ${SUB_PATHLEN_FLAG} --input "${INPUT}" --out-dir "$$OUTDIR/subca-$$TIMESTAMP"; \
		# Optional privileged install step: set INSTALL=true to enable.
		if [ "${INSTALL-}" = "true" ]; then \
			echo "INSTALL=true: performing privileged install of generated artifacts"; \
			sudo mkdir -p /etc/rancher/subca || true; \
			sudo cp -a "$$OUTDIR/subca-$$TIMESTAMP/." /etc/rancher/subca/; \
			echo "Privileged install complete (copied to /etc/rancher/subca/)"; \
		fi;

certs-verify:
	@set -euo pipefail; \
		command -v openssl >/dev/null 2>&1 || { echo "openssl missing"; exit 2; }; \
		echo "openssl: $$(openssl version 2>/dev/null)"; \
		echo "Make sure you move the generated root CA offline and protect private keys.";

certs-assert:
	@set -euo pipefail; \
		if [ -z "${ROOT-}" ] || [ -z "${SUB-}" ]; then echo "Usage: make certs-assert ROOT=path/to/root.crt SUB=path/to/sub.crt"; exit 1; fi; \
		command -v ./certs/scripts/verify-chain.sh >/dev/null 2>&1 || true; \
		./certs/scripts/verify-chain.sh --root "${ROOT}" --sub "${SUB}"; \
		echo "certs-assert: OK";

## Fully automated CA + subCA pipeline
## Usage examples:
##   make certs-auto ROOT_CN="My Root CA" SUB_CN="My Sub CA" SUB_ORG="Example" ROOT_PASS='s3cret' SUB_ENCRYPT=true
## Environment/Make variables supported (all optional with sensible defaults):
##   ROOT_CN, ROOT_PASS, ROOT_KEY, ROOT_CERT, SUB_CN, SUB_ORG, SUB_ENCRYPT, SUB_PASSFILE, OUTDIR (base outputs dir), STAGE_DIR

certs-auto:
	@# Do not run this whole recipe under sudo. It uses sudo internally.
	@if [ "$$(id -u)" -eq 0 ]; then \
		echo "Do not run 'sudo make certs-auto' - run as your user and the recipe will use sudo where needed"; \
		exit 1; \
	fi
	@echo "Running scripts/certs-auto.sh to perform CA automation"
	@chmod +x scripts/certs-auto.sh
	@OUTDIR="${OUTDIR:-outputs/certs}" STAGE_DIR="${STAGE_DIR:-/opt/rke2/stage/certs}" TOKEN_OUTPUT_DIR="${TOKEN_OUTPUT_DIR:-outputs/generated-token}" ROOT_CN="${ROOT_CN}" ROOT_PASS="${ROOT_PASS}" SUB_CN="${SUB_CN}" SUB_ORG="${SUB_ORG}" SUB_ENCRYPT="${SUB_ENCRYPT}" SUB_PASSFILE="${SUB_PASSFILE}" SUB_PATHLEN="${SUB_PATHLEN}" ./scripts/certs-auto.sh
