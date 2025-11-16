#!/usr/bin/env python3
"""
Render an /etc/rancher/rke2/config.yaml fragment from a rkeprep manifest (yaml).
This is a small helper to validate what append_spec_config_extras would write
without executing the full rke2nodeinit server workflow.

Usage: scripts/render_rke2_config.py path/to/manifest.yaml
"""
import sys
import yaml
from pathlib import Path

if len(sys.argv) < 2:
    print("Usage: render_rke2_config.py <manifest.yaml>", file=sys.stderr)
    sys.exit(2)

f = Path(sys.argv[1])
if not f.exists():
    print(f"Manifest not found: {f}", file=sys.stderr)
    sys.exit(2)

doc = yaml.safe_load(f.read_text()) or {}
spec = doc.get('spec', {})

out_lines = []
out_lines.append('debug: true')

# token precedence: token then tokenFile
if 'token' in spec and spec.get('token'):
    out_lines.append(f"token: {spec.get('token')}")
elif 'tokenFile' in spec and spec.get('tokenFile'):
    out_lines.append(f"token-file: \"{spec.get('tokenFile')}\"")

# Scalars mapping
scalars = [
    'cluster-cidr', 'service-cidr', 'cluster-domain', 'enable-servicelb',
    'node-ip', 'bind-address', 'advertise-address'
]

def get_spec_val(spec, key):
    # support camelCase fallback for keys like nodeIp
    if key in spec:
        return spec[key]
    parts = key.split('-')
    camel = parts[0] + ''.join(p.capitalize() for p in parts[1:])
    return spec.get(camel)

for k in scalars:
    v = get_spec_val(spec, k)
    if v is None:
        continue
    # normalize boolean-like
    if isinstance(v, bool):
        out_lines.append(f"{k}: {str(v).lower()}")
    else:
        out_lines.append(f"{k}: {v}")

# Lists
lists = [
    'kube-apiserver-arg', 'kube-controller-manager-arg', 'kube-scheduler-arg',
    'kube-proxy-arg', 'node-taint', 'node-label', 'tls-san', 'cni', 'disable'
]

for k in lists:
    # check kebab and camel
    items = spec.get(k)
    if items is None:
        parts = k.split('-')
        camel = parts[0] + ''.join(p.capitalize() for p in parts[1:])
        items = spec.get(camel)
    if items is None:
        # fallback scalar
        scalar = spec.get(k) or spec.get(camel)
        if scalar is None:
            continue
        # if cni scalar, emit as quoted scalar
        if k == 'cni':
            out_lines.append(f'cni: "{scalar}"')
        else:
            out_lines.append(f"{k}:")
            out_lines.append(f"  - {scalar}")
        continue
    if isinstance(items, list):
        out_lines.append(f"{k}:")
        for it in items:
            out_lines.append(f"  - {it}")

# kubelet-arg defaults (as in the script)
out_lines.append('kubelet-arg:')
out_lines.append('  - resolv-conf=/run/systemd/resolve/resolv.conf')
out_lines.append('  - container-log-max-size=10Mi')
out_lines.append('  - container-log-max-files=5')

print('\n'.join(out_lines))
