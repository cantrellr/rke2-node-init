#!/usr/bin/env python3
"""
Select the best hardened-cni-plugins tag given candidate tag data.
Usage: select_hardened_cni_tag.py <tags_json_path> <hub_json_path> <desired_tag> <rke2_version>
"""
import json
import re
import sys

def load_tags_from_hub(path):
    try:
        with open(path,'r',encoding='utf-8') as fh:
            data=fh.read()
            if not data.strip():
                return []
            j=json.loads(data)
            results=j.get('results',[]) or []
            return [r.get('name') for r in results if r.get('name')]
    except Exception:
        return []

def load_tags_from_skopeo(path):
    try:
        with open(path,'r',encoding='utf-8') as fh:
            data=fh.read()
            if not data.strip():
                return []
            j=json.loads(data)
            return j.get('Tags',[]) or []
    except Exception:
        return []

def semver_key(tag):
    # Parse semver-like tags: v1.2.3, 1.2, 1.2.3-rc1, v1.8.0-build20251110
    # Return tuple: (major, minor, patch, is_prerelease (0 for release), build_ts)
    if not tag:
        return None
    # split into main and suffix (pre-release/build)
    main = tag
    suffix = ''
    if '-' in tag:
        main, suffix = tag.split('-', 1)
    # strip leading v
    if main.startswith('v'):
        main = main[1:]
    parts = main.split('.')
    try:
        major = int(parts[0]) if len(parts) >= 1 and parts[0].isdigit() else None
    except Exception:
        major = None
    if major is None:
        return None
    minor = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    patch = int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0

    # Determine prerelease flag
    is_prerelease = 0
    build_ts = 0
    if suffix:
        # If suffix starts with 'build' and followed by digits, interpret as build timestamp
        m = re.match(r'build(\d{8,})', suffix)
        if m:
            try:
                build_ts = int(m.group(1))
            except Exception:
                build_ts = 0
        else:
            # treat other suffixes as pre-release
            is_prerelease = 1

    return (major, minor, patch, is_prerelease, build_ts)

def choose_tag(tags, desired, rke2):
    desired = (desired or '').strip()
    rke2 = (rke2 or '').lstrip('v')
    # Exact or substring match for desired
    if desired:
        for t in tags:
            if t==desired:
                return t
        for t in tags:
            if desired in t:
                return t
    # Try to match RKE2 major.minor
    if rke2:
        parts=rke2.split('.')
        mm='.'.join(parts[:2]) if len(parts)>=2 else parts[0]
        if mm:
            for t in tags:
                if mm in t:
                    return t
    # Pick highest semver-like tag
    sem_tags=[(semver_key(t),t) for t in tags]
    sem_tags=[(k,t) for k,t in sem_tags if k is not None]
    if sem_tags:
        sem_tags.sort(reverse=True)
        return sem_tags[0][1]
    # Fallback to last tag (best-effort)
    if tags:
        return tags[-1]
    return ''

if __name__=='__main__':
    if len(sys.argv)<5:
        print('',end='')
        sys.exit(0)
    tags_path=sys.argv[1]
    hub_path=sys.argv[2]
    desired=sys.argv[3]
    rke2=sys.argv[4]
    tags = []
    tags = load_tags_from_hub(hub_path)
    if not tags:
        tags = load_tags_from_skopeo(tags_path)
    chosen = choose_tag(tags, desired, rke2)
    print(chosen or '')
