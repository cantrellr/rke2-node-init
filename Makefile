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
		if [ -z "${INPUT-}" ]; then \
			echo "Usage: make certs-sub-ca INPUT=path/to/input.yaml"; exit 1; \
		fi; \
		OUTDIR=$${OUTDIR:-outputs/certs}; \
		TIMESTAMP=$$(date +%Y%m%d-%H%M%S); \
		mkdir -p "$$OUTDIR"; \
		# Optionally forward subordinate key encryption flags from Make invocation
		ENCRYPT_FLAG=""; \
		SUB_PASSFILE_FLAG=""; \
		if [ "${SUB_ENCRYPT-}" = "true" ]; then ENCRYPT_FLAG="--encrypt-sub-key"; fi; \
		if [ -n "${SUB_PASSFILE-}" ]; then SUB_PASSFILE_FLAG="--sub-passfile ${SUB_PASSFILE}"; fi; \
		./certs/scripts/generate-subordinate-ca.sh ${ENCRYPT_FLAG} ${SUB_PASSFILE_FLAG} --input "${INPUT}" --out-dir "$$OUTDIR/subca-$$TIMESTAMP";

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
