# -----------------------------------------------------------------
# HARDENED DOCKERFILE
#  - Current, slim base image (fewer known CVEs)
#  - Multi-stage build - no dev tooling in the final image
#  - Runs as a non-root user
#  - COPY (not ADD) - no surprising remote-fetch/extract behavior
#  - No secrets baked into any layer - injected at runtime via env
#  - HEALTHCHECK included
# -----------------------------------------------------------------
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev

FROM node:20-slim
WORKDIR /app

# Run as a dedicated, unprivileged user rather than root
RUN groupadd -r appuser && useradd -r -g appuser appuser

COPY --from=build /app/node_modules ./node_modules
COPY . .

RUN chown -R appuser:appuser /app
USER appuser

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD node -e "require('http').get('http://localhost:3000/', r => process.exit(r.statusCode === 200 ? 0 : 1)).on('error', () => process.exit(1))"

CMD ["node", "server.js"]
