# AerolVM code-server image: VS Code in the browser, on port 8080.
#
# Built on the official code-server image. Two changes:
#   - No sign-in page (--auth none). The docs share the port with
#     visibility "token", so the AerolVM server lets in only someone with a
#     sandbox token for it. Never share this port as public.
#   - No passwordless sudo. The editor and its terminal run as uid 1000,
#     and stay that way. Add tools with RUN lines above "USER 1000".
#
# The file is self-contained (no COPY), so the SDKs' image builder, which
# sends only a Dockerfile, builds it as is. Docs: /vscode-in-browser/.
FROM codercom/code-server:4.144.0

USER root
RUN rm -f /etc/sudoers.d/nopasswd \
 && mkdir -p /home/coder/project \
 && chown 1000:1000 /home/coder/project

USER 1000
WORKDIR /home/coder/project
EXPOSE 8080
ENTRYPOINT ["/usr/bin/entrypoint.sh", "--bind-addr", "0.0.0.0:8080", "--auth", "none", "--disable-telemetry", "--disable-update-check", "/home/coder/project"]
