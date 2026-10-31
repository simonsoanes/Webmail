# syntax=docker/dockerfile:1
# Nullify.WebMail server image. Build from the repository root:
#   docker build -t nullify-webmail .
# CI gates: `docker build --target test .` runs the .NET test suite inside the SDK image, and
# `docker build --target test-pgp .` runs the OpenPGP interop tests against GnuPG and OpenPGP.js.

ARG DOTNET_VERSION=10.0
ARG NODE_VERSION=22

# The publish output is portable IL (no app host), so it is built on the builder's own platform and only
# the runtime stage differs per architecture; multi-arch builds then need no emulated SDK.
FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG VERSION=0.0.0
WORKDIR /src
COPY Nullify.WebMail.slnx ./
COPY src/Nullify.WebMail/Nullify.WebMail.csproj src/Nullify.WebMail/
COPY src/Nullify.WebMail.Shared/Nullify.WebMail.Shared.csproj src/Nullify.WebMail.Shared/
COPY tests/Nullify.WebMail.Tests/Nullify.WebMail.Tests.csproj tests/Nullify.WebMail.Tests/
RUN dotnet restore Nullify.WebMail.slnx
COPY src/ src/
# Restore again now the sources are here: the SDK only adds Microsoft.AspNetCore.App.Internal.Assets
# (which ships _framework/blazor.web.js) once it can see .razor files, and the layer-cached restore
# above runs with just the project files. Without it the published UI never becomes interactive.
RUN dotnet publish src/Nullify.WebMail/Nullify.WebMail.csproj -c Release -o /app \
      -p:UseAppHost=false -p:Version="$VERSION"

FROM build AS test
COPY tests/Nullify.WebMail.Tests/ tests/Nullify.WebMail.Tests/
RUN dotnet test tests/Nullify.WebMail.Tests -c Release --no-restore --logger "console;verbosity=normal"

FROM node:${NODE_VERSION}-bookworm-slim AS test-pgp
RUN apt-get update && apt-get install -y --no-install-recommends gnupg && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY tests/pgp/package.json tests/pgp/package-lock.json tests/pgp/
RUN cd tests/pgp && npm ci --no-audit --no-fund
COPY src/Nullify.WebMail/wwwroot/js/pgp/ src/Nullify.WebMail/wwwroot/js/pgp/
COPY src/Nullify.WebMail/wwwroot/js/pgp-bridge.js src/Nullify.WebMail/wwwroot/js/passkey.js src/Nullify.WebMail/wwwroot/js/
COPY tests/pgp/ tests/pgp/
RUN cd tests/pgp && npm test

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION} AS final
LABEL org.opencontainers.image.title="Nullify.WebMail" \
      org.opencontainers.image.description="Self-hosted IMAP/SMTP webmail with calendar, contacts, files and OpenPGP" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.authors="Simon Soanes" \
      org.opencontainers.image.url="https://github.com/simonsoanes/Webmail"
WORKDIR /app
# appsettings.json binds Kestrel to localhost:5000 for local runs; listen on all interfaces in the container.
ENV Kestrel__Endpoints__Http__Url=http://+:8080 \
    Storage__DataDirectory=/data \
    DOTNET_NOLOGO=true
# /data holds the SQLite database and the data protection keys that encrypt cookies and stored secrets.
RUN mkdir -p /data && chown "$APP_UID":"$APP_UID" /data
COPY --from=build /app .
USER $APP_UID
VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["dotnet", "Nullify.WebMail.dll"]
