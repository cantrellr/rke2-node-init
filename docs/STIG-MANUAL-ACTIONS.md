# Manual STIG Actions

## Overview

The `scripts/apply-stigs.sh` and `scripts/apply-cluster-stigs.sh` utilities provide automated hardening for many DISA Security Technical Implementation Guide (STIG) requirements.  However, some controls cannot be remediated programmatically.  Administrators must manually validate system state, update documentation, or perform one‑off configuration changes.  This document collects those manual actions so that they can be incorporated into operational procedures and evidence packages.

The lists below are organized by subject area (operating system, Kubernetes/RKE2 control plane and workloads) and reference applicable STIG identifiers where possible.  Use the DISA XCCDF documents for full vulnerability discussions and fix texts.

> **Note:** This checklist is not exhaustive.  Always review the latest STIG releases and policy guidance to ensure complete coverage.

## Ubuntu 24.04 LTS Manual Tasks

The following tasks are derived from the Ubuntu STIG and common hardening practices.  They apply to all cluster nodes and supporting hosts.

- **Patch management and package integrity** – Regularly apply security updates using `apt update && apt full-upgrade`.  Review [CVEs](https://ubuntu.com/security/cves) and ensure third‑party packages are signed and verified.  Document patch baselines and compliance.
- **User accounts and passwords** – Configure password complexity (length, character classes) and rotation intervals in `/etc/login.defs` and PAM modules.  Disable unused local accounts and ensure sudo access is limited to authorized personnel.  Enforce account lockout after consecutive failed logon attempts.  These tasks correspond to controls such as SRG‑OS‑000002 and SRG‑OS‑000021 in the Ubuntu STIG.
- **SSH hardening** – Verify that SSH is configured to use protocol 2, strong ciphers, and key‑based authentication (`PasswordAuthentication no`).  Restrict root login and limit access via `AllowUsers` or `AllowGroups`.  Disable X11 forwarding and ensure idle session timeouts are set (e.g. `ClientAliveInterval` and `ClientAliveCountMax`).
- **Log management and auditd** – Ensure `auditd` is installed, enabled, and configured to log file accesses, privilege escalation, and network events.  Maintain audit log retention for at least 30 days and forward logs to a centralized log server if required by policy.  Regularly review logs for suspicious activity.
- **Services and daemons** – Disable unnecessary services (e.g. FTP, Telnet, rlogin) and remove unused packages.  Harden systemd unit files to prevent automatic restarting of compromised services.  Verify that only essential listening ports are open.  Use the provided `k8s-node-firewalld-zone-hardening.sh` to configure host‑level firewalld zones and sysctl parameters.
- **Filesystems and permissions** – Mount filesystems with appropriate options (`nosuid`, `nodev`, `noexec` as applicable).  Set strict file permissions on system configuration files, especially `/etc/rancher/rke2/config.yaml`, `/var/lib/rancher/rke2`, and `/var/lib/etcd`.  The automated script sets baseline permissions, but administrators should verify that no world‑writable files remain and that sensitive files are owned by `root`.

## RKE2 Control Plane Manual Tasks

The `scripts/apply-stigs.sh` script configures many RKE2 parameters (e.g. TLS minimum version, cipher suites, disabling anonymous authentication, enforcing webhook authorization, enabling audit logging and file protection)【745477098426797†L51-L81】.  The following controls still require manual implementation or verification:

- **Verify configuration changes** – Confirm that all `kube-apiserver-arg` and `kubelet-arg` values recommended by the STIG are present in `/etc/rancher/rke2/config.yaml`.  For example, ensure `anonymous-auth=false`, `authorization-mode=Webhook`, `audit-log-maxage=30`, and other parameters.  Restart the RKE2 service after edits and validate with `ps -ef | grep kube-apiserver` or `grep kubelet` as described in the STIG.
- **Remove or disable unused Kubernetes components** – If PodSecurityPolicy, node local DNS, or built‑in cloud providers are unused, disable or remove them to reduce attack surface.  This may involve editing cluster manifests under `/var/lib/rancher/rke2/server/manifests` and ensuring that only essential add‑ons are enabled.
- **Session termination and idle timeouts** – RKE2 does not expose session timeout settings via configuration; instead, administrators should implement RBAC policies and external identity providers that enforce session expiration and re‑authentication.
- **Root CA and certificate rotation** – Periodically rotate internal certificates used by etcd and the API server.  Document the rotation process and ensure certificate files are protected with appropriate permissions.  Some of these tasks may need to be coordinated with Rancher support.
- **Image provenance and vulnerability scanning** – Establish a trusted image registry and implement continuous vulnerability scanning.  Only deploy signed and scanned container images.  This is largely a procedural control and must be enforced via CI/CD pipelines and policy tools (e.g. Kyverno, OPA Gatekeeper).

## Kubernetes Cluster/Workload Manual Tasks

Automated scripts cannot account for every application workload.  The following manual tasks help ensure that workloads comply with the Kubernetes and RKE2 STIGs:

- **Namespace and NetworkPolicy review** – Use `kubectl get networkpolicy --all-namespaces` to verify that each namespace has restrictive ingress and egress policies.  Default deny policies should be applied only after confirming application‑specific policies permit required traffic.  Review and adjust policies when deploying new services.
- **Pod Security Standards** – Ensure that each namespace has appropriate Pod Security Admission (PSA) labels.  The automated cluster script sets `restricted` for selected namespaces.  Review system namespaces (e.g. `kube-system`, `calico-system`, `cilium`, `linkerd`) and apply `privileged` or `baseline` labels as appropriate.  Investigate pods that run as root or with excessive capabilities.
- **Secrets management** – Verify that Kubernetes Secrets are encrypted at rest (`--encryption-provider-config`) and rotated regularly.  Avoid storing secrets in plaintext ConfigMaps or environment variables.  Integrate with an external secret management system when possible.
- **RBAC and least privilege** – Audit ClusterRoles, ClusterRoleBindings, Roles, and RoleBindings to ensure that service accounts have only the permissions they require.  Remove unused accounts and restrict use of the `system:masters` group.
- **Etcd backup and recovery** – Establish a routine to back up the etcd datastore (e.g. `rke2 etcd snapshot save`) and test restoration.  Securely store backups and restrict access to backup files.
- **Persistent storage and host path volumes** – Avoid using hostPath volumes unless absolutely necessary.  When required, restrict paths and set `readOnly: true` if possible.  Use CSI drivers with encryption and authentication support.
- **Control plane node isolation** – Schedule only control plane components on control nodes by tainting them (`node-role.kubernetes.io/control-plane:NoSchedule`).  Ensure that workloads are not scheduled on control plane nodes unless explicitly tolerated.

## Evidence and Documentation

For each manual action taken, record the date, responsible individual, commands executed, and resulting state.  Capture command outputs (e.g. `kubectl describe namespace`, `ls -l /etc/rancher/rke2`) and include them in the STIG compliance package.  The supplied `docs/STIG-CHECKLIST.md` provides a template for documenting these actions【207244720952850†L33-L137】.

## Additional References

* **RKE2 STIG README** – Details the automated controls implemented by `apply-stigs.sh` and identifies additional manual controls【745477098426797†L51-L81】.
* **STIG Checklist** – Provides a checklist and evidence table for manual verification of operating system, Kubernetes, and RKE2 controls【207244720952850†L33-L137】.
* **DISA STIG Releases** – Always refer to the latest STIG XCCDF documents included in this repository (`U_CAN_Ubuntu_24-04_LTS_V1R5_STIG`, `U_Kubernetes_V2R6_STIG`, `U_RGS_RKE2_V2R6_STIG`) for full guidance.
