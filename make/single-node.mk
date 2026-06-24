# Optional helper targets for single-node RKE2 workflows.
# Include manually from a local Makefile if desired, or run the commands directly.

SINGLE_NODE_CONFIG ?= configs/single-node/production-server.yaml
SINGLE_NODE_MODE ?= production

.PHONY: single-node-render single-node-apply single-node-server single-node-verify single-node-test

single-node-render:
	bash bin/rke2-single-node-profile.sh render -f "$(SINGLE_NODE_CONFIG)" --mode "$(SINGLE_NODE_MODE)"

single-node-apply:
	sudo bash bin/rke2-single-node-profile.sh apply -f "$(SINGLE_NODE_CONFIG)" --mode "$(SINGLE_NODE_MODE)"

single-node-server:
	sudo bash bin/rke2-single-node-profile.sh server -f "$(SINGLE_NODE_CONFIG)" --mode "$(SINGLE_NODE_MODE)" -y

single-node-verify:
	sudo bash bin/rke2-single-node-profile.sh verify --mode "$(SINGLE_NODE_MODE)"

single-node-test:
	bash tests/test-single-node-profile.sh
