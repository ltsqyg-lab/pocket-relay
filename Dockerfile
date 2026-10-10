# Pocket relay — zero dependencies, Node.js 22.
#   docker build -t pocket-relay .
#   docker run -d --name pocket-relay --restart unless-stopped -p 8443:8443 -v pocket-relay:/var/lib/pocket-relay pocket-relay
#   docker logs pocket-relay       # the line to paste into the Pocket app: Settings → Server → Add self-hosted server
# Mainland China edition (talks only to api.pocketcli.cn): docker build --build-arg RELAY_EDITION=cn -t pocket-relay .
# (or -e RELAY_EDITION=cn on docker run)
# No configuration needed: the relay makes its own certificate and asks the coordination server for this server's
# public IP. Settings: RELAY_* environment variables (e.g. -e RELAY_PUBLIC_URL=https://203.0.113.7:8443) or a file
# mounted at /etc/pocket-relay/relay.json (see relay.example.json). The volume keeps the certificate, the claim and
# the data across upgrades.
FROM node:22-alpine
ARG RELAY_EDITION=intl
ENV NODE_ENV=production RELAY_EDITION=${RELAY_EDITION}
WORKDIR /app
COPY package.json LICENSE README.md README.zh-CN.md ./
COPY src ./src
RUN mkdir -p /var/lib/pocket-relay && chown node:node /var/lib/pocket-relay
USER node
VOLUME ["/var/lib/pocket-relay"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD ["node", "src/main.mjs", "--health"]
CMD ["node", "src/main.mjs"]
