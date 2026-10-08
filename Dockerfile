# Pocket relay — zero dependencies, Node.js 22.
#   docker build -t pocket-relay .
#   docker run -d --name pocket-relay -p 443:8443 \
#     -v /srv/pocket-relay:/var/lib/pocket-relay -v /etc/pocket-relay:/etc/pocket-relay:ro \
#     pocket-relay
# Configuration: /etc/pocket-relay/relay.json (see relay.example.json) and/or RELAY_* environment variables.
FROM node:22-alpine
ENV NODE_ENV=production
WORKDIR /app
COPY package.json LICENSE README.md ./
COPY src ./src
RUN mkdir -p /var/lib/pocket-relay && chown node:node /var/lib/pocket-relay
USER node
VOLUME ["/var/lib/pocket-relay"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["node", "src/main.mjs", "--health"]
CMD ["node", "src/main.mjs"]
