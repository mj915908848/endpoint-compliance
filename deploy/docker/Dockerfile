# Build from the repository root: docker build -f deploy/docker/Dockerfile -t compliance-server .
FROM node:22-bookworm-slim AS ui
WORKDIR /src/ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS server
WORKDIR /src
COPY global.json Directory.Build.props ./
COPY src/Compliance.Core/ src/Compliance.Core/
COPY src/Compliance.Server/ src/Compliance.Server/
COPY --from=ui /src/ui/dist ui/dist
RUN dotnet publish src/Compliance.Server -c Release -o /app

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=server /app ./
# The signing key lives here; a named volume mounted on it inherits this ownership.
RUN mkdir -p /var/lib/compliance && chown app:app /var/lib/compliance
USER app
ENV ASPNETCORE_URLS=https://+:8443 \
    Compliance__Storage=Postgres \
    Compliance__SigningKeyPath=/var/lib/compliance/signing.key
EXPOSE 8443
ENTRYPOINT ["dotnet", "Compliance.Server.dll"]
