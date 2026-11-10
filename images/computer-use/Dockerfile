# AerolVM computer-use image: a Linux desktop you can watch in a web page,
# and a Chromium browser that programs drive through its DevTools port.
#
#   Xvfb       a screen in memory (display :99)
#   Openbox    a small window manager
#   Chromium   the browser, with DevTools on 127.0.0.1:9222
#   x11vnc     shares the screen over VNC, on localhost only
#   noVNC      shows that screen in a web page on port 6080
#   Playwright (Python) to drive the browser over CDP from inside
#
# The file is self-contained (no COPY), so the SDKs' image builder, which
# sends only a Dockerfile, builds it as is. Docs: /computer-use/.
#
# The base image is pinned by digest, so a re-pushed tag cannot change what
# we build. Dependabot moves the tag and the digest together.
FROM python:3.12.16-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    DISPLAY=:99

# Debian's own Chromium, so one browser serves both the desktop and
# Playwright (connect_over_cdp), with no second browser download.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates chromium curl fonts-liberation fonts-noto-color-emoji \
      novnc openbox procps websockify x11-utils x11vnc xvfb \
 && rm -rf /var/lib/apt/lists/*

# Playwright and every package it pulls in, each pinned to the sha256 of
# the wheel pip picks here on amd64 and on arm64. With --require-hashes,
# pip stops if PyPI serves a different file or if a dependency is missing
# from the list. --require-hashes must come before -r: OpenSSF Scorecard
# reads the pip arguments in order and stops at that flag.
#
# To move Playwright, run this in the base image, once per platform, and
# copy each package's version and sha256 into the list:
#   pip install --dry-run --ignore-installed --only-binary=:all: \
#     --report /tmp/r.json playwright==<version>
RUN printf '%s\n' \
  'playwright==1.64.1 --hash=sha256:577b8d88778c245cfbd145ae17cf53044f084b1b46c55c69081d4069d56057e2 --hash=sha256:a29fda44725e11b0b625c4bff6458a1f6dbee97b88c9788d12e18a8344458c2d' \
  'greenlet==3.5.6 --hash=sha256:975736b002ed080d124cf81a79cb7e05cb26d6b3f5c7a7b651c0fcce70353aa1 --hash=sha256:e85880b538e59a59f55117b81f208a6660ad5ac328aad9305f812d9b8bc67a0f' \
  'pyee==14.0.0 --hash=sha256:3ac2d3229a9677f7de2c33d7f52fe25b638a46b19c413fea2edc8c6d0a644e4d' \
  'typing-extensions==4.16.0 --hash=sha256:481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8' \
  > /tmp/requirements.txt \
 && pip install --require-hashes --only-binary=:all: -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# The start script. Each process logs to ~/.desktop/logs. Chromium runs in
# a loop so closing its window in the desktop does not take DevTools away.
# x11vnc listens on localhost only: the one way in is noVNC on 6080.
RUN printf '%s\n' \
  '#!/bin/sh' \
  'set -eu' \
  'export DISPLAY="${DISPLAY:-:99}"' \
  'GEOMETRY="${SCREEN_GEOMETRY:-1280x800x24}"' \
  'WINDOW="${WINDOW_SIZE:-1280,800}"' \
  'STATE="${HOME}/.desktop"' \
  'LOGS="${STATE}/logs"' \
  'mkdir -p "${LOGS}" "${STATE}/chromium"' \
  'Xvfb "${DISPLAY}" -screen 0 "${GEOMETRY}" -nolisten tcp >"${LOGS}/xvfb.log" 2>&1 &' \
  'for _ in $(seq 1 50); do xdpyinfo >/dev/null 2>&1 && break; sleep 0.2; done' \
  'openbox >"${LOGS}/openbox.log" 2>&1 &' \
  '( while true; do' \
  '    chromium --no-sandbox --no-first-run --no-default-browser-check \' \
  '      --disable-dev-shm-usage --disable-gpu --password-store=basic \' \
  '      --remote-debugging-port=9222 --user-data-dir="${STATE}/chromium" \' \
  '      --window-position=0,0 --window-size="${WINDOW}" "${START_URL:-about:blank}" \' \
  '      >>"${LOGS}/chromium.log" 2>&1' \
  '    sleep 1' \
  '  done ) &' \
  'x11vnc -display "${DISPLAY}" -forever -shared -nopw -localhost -rfbport 5900 \' \
  '  >"${LOGS}/x11vnc.log" 2>&1 &' \
  'exec websockify --web=/usr/share/novnc/ 6080 localhost:5900 >"${LOGS}/websockify.log" 2>&1' \
  > /usr/local/bin/start-desktop \
 && chmod 755 /usr/local/bin/start-desktop \
 && ln -sf /usr/share/novnc/vnc.html /usr/share/novnc/index.html

RUN useradd --create-home --uid 1000 --shell /bin/bash desktop
USER 1000
WORKDIR /home/desktop

EXPOSE 6080 9222
ENTRYPOINT ["/usr/local/bin/start-desktop"]
