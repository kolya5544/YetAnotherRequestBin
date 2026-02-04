# YetAnotherRequestBin
## Lightweight HTTP request capture & inspection service

YetAnotherRequestBin is a small ASP.NET Core app that accepts inbound HTTP requests (any method), captures headers + body, stores them on disk, and can optionally forward a formatted summary to a Discord webhook.

- Capture requests to disk (`/l/{key}`)
- Capture + notify Discord (`/w/{key}`)
- Capture + return a matching asset (`/r/{key}`)
- Capture + render request as a PNG (`/i/{key}`)

## Main features

- Accepts: GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD
- Per-key storage: requests saved under `logs/{key}/`
- Smart body handling:
  - Text bodies up to 16 KB stored as `.txt`
  - Larger bodies or binary bodies stored as `.bin` (raw bytes streamed to disk)
- Display-safe previews:
  - Body preview truncated to 1 KB for PNG rendering and Discord embeds
- Asset responder (`/r/{key}`):
  - If `assets/{key}` or `assets/{key}.*` exists, returns that file (while still logging the request)
- PNG inspector (`/i/{key}`):
  - Returns a PNG rendering of the request for quick inspection
  - Response sets no-cache headers

## Endpoints

- GET `/`
  - Health text.

- ANY `/l/{key}`
  - Logs incoming request to `logs/{key}/req_{guid}.txt|.bin`
  - Returns request ID + log path.

- ANY `/w/{key}`
  - Logs request and queues a Discord webhook send (if configured).

- ANY `/r/{key}`
  - Logs request and tries to return an asset from `assets/` matching `{key}`.

- ANY `/i/{key}`
  - Logs request and returns a PNG rendering of the request summary.

## Configuration

### Discord webhook

Set `Webhooks:DiscordUrl` using an environment variable (recommended):

    Webhooks__DiscordUrl=https://discord.com/api/webhooks/...

Or set it in `appsettings.json`:

    "Webhooks": {
      "DiscordUrl": ""
    }

## Run (standalone)

Build:
```
dotnet build
```

Run:
```
dotnet run
```

By default, Kestrel listens on:
```
http://0.0.0.0:5042
```

Files are created relative to the app base directory:

- `./logs`
- `./assets`

## systemd (Linux)

1) Publish the app:
```
dotnet publish -c Release -o /opt/yet-another-requestbin
```

2) Create a service:

Create `/etc/systemd/system/yet-another-requestbin.service`:
```
[Unit]
Description=YetAnotherRequestBin
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/yet-another-requestbin
ExecStart=/usr/bin/dotnet /opt/yet-another-requestbin/YetAnotherRequestBin.dll
Restart=always
RestartSec=5
Environment=ASPNETCORE_URLS=http://0.0.0.0:5042
Environment=Webhooks__DiscordUrl=https://discord.com/api/webhooks/...

[Install]
WantedBy=multi-user.target
```

3) Enable + start:
```
sudo systemctl daemon-reload
sudo systemctl enable yet-another-requestbin
sudo systemctl start yet-another-requestbin
sudo systemctl status yet-another-requestbin
```

Note: Update `YetAnotherRequestBin.dll` to the actual published DLL name shown in `/opt/yet-another-requestbin/`.

## Docker

Create `Dockerfile`:
```
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 5042
ENV ASPNETCORE_URLS=http://0.0.0.0:5042

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY . .
RUN dotnet publish -c Release -o /out

FROM base AS final
WORKDIR /app
COPY --from=build /out ./
RUN mkdir -p /app/logs /app/assets
ENTRYPOINT ["dotnet", "YetAnotherRequestBin.dll"]
```

Build:
```
docker build -t yetanotherrequestbin .
```

Run:
```
docker run --rm -p 5042:5042 \
    -e Webhooks__DiscordUrl="https://discord.com/api/webhooks/..." \
    -v "$(pwd)/logs:/app/logs" \
    -v "$(pwd)/assets:/app/assets" \
    yetanotherrequestbin
```

Note: Update `YetAnotherRequestBin.dll` to the actual published DLL name (same as above).

## License

MIT