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
FROM python:3.12.16-slim-bookworm

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

RUN pip install playwright==1.64.1

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
