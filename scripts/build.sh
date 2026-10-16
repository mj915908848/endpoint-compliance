#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
dotnet_cmd="${DOTNET_CMD:-dotnet}"
(cd ui && npm ci && npm test && npm run build)
"$dotnet_cmd" run --project tests/Compliance.Core.Tests
"$dotnet_cmd" test tests/Compliance.Server.Tests
"$dotnet_cmd" run --project tests/Compliance.Agent.Tests
"$dotnet_cmd" publish src/Compliance.Server -c Release -r win-x64 --self-contained true -p:PublishTrimmed=true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -o artifacts/package/server-windows-x64
"$dotnet_cmd" publish src/Compliance.Agent -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/package/agent-windows-x64
"$dotnet_cmd" publish src/Compliance.Tray -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -o artifacts/package/tray-windows-x64
"$dotnet_cmd" publish src/Compliance.Server -c Release -r linux-x64 --self-contained true -p:PublishTrimmed=true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=none -o artifacts/package/server-linux-x64
