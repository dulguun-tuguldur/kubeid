# ABOUTME: Linux test image for exercising `sudo kubeid issue` with real sudo, NSS and privilege drop.
# ABOUTME: kubectl is the integration stub (throwaway CA signer); users/groups stand in for FreeIPA.
FROM python:3.12-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends sudo \
 && rm -rf /var/lib/apt/lists/*

RUN groupadd k8s-loans-dev \
 && groupadd k8s-platform-admin \
 && useradd -m -s /bin/bash -G k8s-loans-dev alice \
 && useradd -m -s /bin/bash -G k8s-platform-admin bob \
 && useradd -m -s /bin/bash mallory \
 && echo 'alice,bob,mallory ALL=(root) NOPASSWD: /usr/local/bin/kubeid' > /etc/sudoers.d/kubeid \
 && chmod 0440 /etc/sudoers.d/kubeid

COPY . /src
RUN python -m venv /opt/kubeid \
 && /opt/kubeid/bin/pip install --no-cache-dir --quiet /src \
 && ln -s /opt/kubeid/bin/kubeid /usr/local/bin/kubeid

# Stub kubectl on sudo's secure_path. sudo resets env, so the wrapper sets the state dir.
RUN printf '#!/bin/sh\nexec env STUB_KUBECTL_STATE=/var/lib/stub-kubectl /opt/kubeid/bin/python /src/tests/integration/stub_kubectl.py "$@"\n' \
      > /usr/local/bin/kubectl \
 && chmod 0755 /usr/local/bin/kubectl \
 && /opt/kubeid/bin/python /src/tests/e2e_sudo/setup_container.py
