using Microsoft.AspNetCore.StaticFiles;
using SkiaSharp;
using System.Buffers;
using System.Net;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

// Used for /w Discord webhook
builder.Services.AddHttpClient("discord", c =>
{
    c.Timeout = TimeSpan.FromSeconds(10);
});

builder.Services.AddOptions<WebhookOptions>()
    .Bind(builder.Configuration.GetSection("Webhooks"));

var app = builder.Build();

var baseDir = AppContext.BaseDirectory;
var logsRoot = Path.Combine(baseDir, "logs");
var assetsRoot = Path.Combine(baseDir, "assets");
Directory.CreateDirectory(logsRoot);
Directory.CreateDirectory(assetsRoot);

var anyMethods = new[] { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD" };

app.MapGet("/", () => @"YetAnotherRequestBin is running.");

app.MapMethods("/l/{key}", anyMethods, async (HttpContext ctx, string key) =>
{
    var res = await RequestLogger.LogAsync(ctx, key, logsRoot, includeBodyInDisplay: true);
    return Results.Text($"OK\nid={res.Id}\nfile={res.RelativeLogPath}\n");
});

app.MapMethods("/w/{key}", anyMethods, async (
    HttpContext ctx,
    string key,
    IHttpClientFactory httpClientFactory,
    Microsoft.Extensions.Options.IOptions<WebhookOptions> webhookOptions) =>
{
    var res = await RequestLogger.LogAsync(ctx, key, logsRoot, includeBodyInDisplay: true);

    var discordWebhookUrl = webhookOptions.Value.DiscordUrl;

    _ = DiscordWebhook.TrySendAsync(
        httpClientFactory.CreateClient("discord"),
        discordWebhookUrl,
        res,
        ctx.RequestAborted
    );

    return Results.Text($"OK (webhook queued)\nid={res.Id}\nfile={res.RelativeLogPath}\n");
});

app.MapMethods("/r/{key}", anyMethods, async (HttpContext ctx, string key) =>
{
    var res = await RequestLogger.LogAsync(ctx, key, logsRoot, includeBodyInDisplay: true);

    if (AssetResolver.TryResolve(assetsRoot, res.SafeKeyForFs, out var assetPath, out var contentType))
        return Results.File(assetPath!, contentType: contentType);

    return Results.NotFound($"Logged as {res.RelativeLogPath}, but asset not found for key='{res.SafeKeyForFs}'.");
});

app.MapMethods("/i/{key}", anyMethods, async (HttpContext ctx, string key) =>
{
    // If ?r= is present => temporary redirect (302) and exit early
    var r = ctx.Request.Query["r"].ToString();
    if (!string.IsNullOrEmpty(r))
    {
        // Basic CRLF guard (avoid header injection)
        if (r.Contains('\r') || r.Contains('\n'))
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            await ctx.Response.WriteAsync("Invalid redirect URL.");
            return;
        }

        ctx.Response.Redirect(r, permanent: false); // 302
        return;
    }

    try
    {
        // Log first, and reuse the same display text for rendering
        var res = await RequestLogger.LogAsync(ctx, key, logsRoot, includeBodyInDisplay: true);

        var pngBytes = PngRenderer.RenderTextToPng(res.DisplayText);

        ctx.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate, max-age=0";
        ctx.Response.Headers.Pragma = "no-cache";
        ctx.Response.Headers.Expires = "0";

        ctx.Response.StatusCode = StatusCodes.Status200OK;
        ctx.Response.ContentType = "image/png";
        ctx.Response.ContentLength = pngBytes.Length;
        await ctx.Response.Body.WriteAsync(pngBytes);
    }
    catch (Exception ex)
    {
        var errText = $"ERROR\n\n{ex.GetType().Name}: {ex.Message}\n\n{ex.StackTrace}";
        var pngBytes = PngRenderer.RenderTextToPng(errText);

        ctx.Response.StatusCode = StatusCodes.Status500InternalServerError;
        ctx.Response.ContentType = "image/png";
        ctx.Response.ContentLength = pngBytes.Length;
        await ctx.Response.Body.WriteAsync(pngBytes);
    }
});

app.Run();

sealed class WebhookOptions
{
    public string? DiscordUrl { get; init; }
}

// ===========================
// Logging / capture core
// ===========================

static class RequestLogger
{
    // Your rules:
    // - if request includes a text body -> store in .txt
    // - if body exceeds 16 KB OR is binary -> store as req_{id}.bin
    public const int TextBodyMaxBytes = 16 * 1024;

    // For PNG and Discord we keep it readable (don’t blow up)
    public const int DisplayBodyMaxBytes = 1024;

    // Sniff a bit more than 16 KB so we can decide "exceeds 16 KB" without reading whole body twice
    private const int SniffLimit = TextBodyMaxBytes + 1;

    public static async Task<LogResult> LogAsync(HttpContext ctx, string keyRaw, string logsRoot, bool includeBodyInDisplay)
    {
        var id = Guid.NewGuid().ToString("D");
        var nowUtc = DateTimeOffset.UtcNow;

        var safeKey = FsSafeKey(keyRaw);
        var logDir = Path.Combine(logsRoot, safeKey);
        Directory.CreateDirectory(logDir);

        var ip = GetBestIp(ctx);

        var req = ctx.Request;

        // Build header text (human-friendly, used in txt + display + bin prefix)
        var headerText = BuildHeaderText(nowUtc, ip, req);

        // Read prefix up to sniff limit, then decide txt vs bin, then stream remainder accordingly
        var prefixMs = new MemoryStream(capacity: SniffLimit);
        var displayPrefixMs = new MemoryStream(capacity: DisplayBodyMaxBytes);

        // Read initial bytes up to SniffLimit
        var buf = ArrayPool<byte>.Shared.Rent(81920);
        try
        {
            int read;
            while (prefixMs.Length < SniffLimit &&
                   (read = await req.Body.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, SniffLimit - prefixMs.Length)), ctx.RequestAborted)) > 0)
            {
                prefixMs.Write(buf, 0, read);

                // Also capture display prefix (up to DisplayBodyMaxBytes)
                if (displayPrefixMs.Length < DisplayBodyMaxBytes)
                {
                    var remaining = (int)Math.Min(read, DisplayBodyMaxBytes - displayPrefixMs.Length);
                    if (remaining > 0) displayPrefixMs.Write(buf, 0, remaining);
                }
            }

            var prefix = prefixMs.ToArray();
            var hasBody = prefix.Length > 0 || (req.ContentLength.HasValue && req.ContentLength.Value > 0);

            // Determine "exceeds 16 KB"
            var exceedsTextLimit =
                (req.ContentLength.HasValue && req.ContentLength.Value > TextBodyMaxBytes) ||
                prefix.Length > TextBodyMaxBytes;

            // Determine binary vs text
            var isBinary = hasBody && IsBinaryBody(req.ContentType, prefix);

            var useBin = hasBody && (exceedsTextLimit || isBinary);

            var fileExt = useBin ? "bin" : "txt";
            var fileName = $"req_{id}.{fileExt}";
            var logPath = Path.Combine(logDir, fileName);

            // Prepare display text (for /i and Discord embed snippet)
            var displayText = BuildDisplayText(headerText, req, hasBody, useBin, displayPrefixMs.ToArray(), ip);

            // Write log file
            if (!useBin)
            {
                // Body must be text and <=16 KB
                using var fs = new FileStream(logPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                    bufferSize: 64 * 1024, options: FileOptions.Asynchronous | FileOptions.SequentialScan);

                await WriteUtf8Async(fs, headerText + "\n");

                if (hasBody)
                {
                    // Collect the remainder (should stay small)
                    using var bodyMs = new MemoryStream();
                    bodyMs.Write(prefix, 0, prefix.Length);

                    await req.Body.CopyToAsync(bodyMs, ctx.RequestAborted);

                    var bodyBytes = bodyMs.ToArray();
                    var bodyText = DecodeUtf8Lossless(bodyBytes);

                    await WriteUtf8Async(fs, bodyText);
                }
            }
            else
            {
                // .bin: text prefix + delimiter + raw body bytes (prefix + remainder streamed)
                using var fs = new FileStream(logPath, FileMode.CreateNew, FileAccess.Write, FileShare.Read,
                    bufferSize: 64 * 1024, options: FileOptions.Asynchronous | FileOptions.SequentialScan);

                await WriteUtf8Async(fs,
                    headerText +
                    "\n---- BODY (raw bytes) ----\n" +
                    $"Content-Type: {req.ContentType ?? "unknown"}\n" +
                    $"Content-Length: {(req.ContentLength?.ToString() ?? "unknown")}\n\n");

                if (prefix.Length > 0)
                    await fs.WriteAsync(prefix, ctx.RequestAborted);

                // Stream the remainder directly (no memory blowups)
                await req.Body.CopyToAsync(fs, ctx.RequestAborted);
            }

            return new LogResult(
                Id: id,
                TimestampUtc: nowUtc,
                RemoteIp: ip,
                SafeKeyForFs: safeKey,
                Method: req.Method,
                Path: $"{req.PathBase}{req.Path}",
                QueryString: req.QueryString.ToString(),
                ContentType: req.ContentType,
                ContentLength: req.ContentLength,
                LoggedAsBinary: useBin,
                AbsoluteLogPath: logPath,
                RelativeLogPath: $"logs/{safeKey}/{fileName}",
                DisplayText: displayText
            );
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buf);
        }
    }

    private static string BuildHeaderText(DateTimeOffset nowUtc, string ip, HttpRequest req)
    {
        var sb = new StringBuilder(2048);

        sb.Append("UTC: ").Append(nowUtc.ToString("O")).AppendLine();
        sb.Append("IP: ").Append(ip).AppendLine();

        sb.Append(req.Method)
          .Append(' ')
          .Append(req.PathBase)
          .Append(req.Path)
          .Append(req.QueryString)
          .AppendLine();

        foreach (var header in req.Headers.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase))
        {
            if (header.Key.Equals("X-Forwarded-For", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("X-Real-IP", StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var v in header.Value)
                sb.Append(header.Key).Append(": ").Append(v).AppendLine();
        }

        return sb.ToString();
    }

    private static string BuildDisplayText(string headerText, HttpRequest req, bool hasBody, bool loggedAsBin, byte[] displayPrefix, string ip)
    {
        var sb = new StringBuilder(headerText.Length + 2048);
        sb.Append(headerText).AppendLine();

        if (!hasBody)
            return sb.ToString();

        if (!loggedAsBin)
        {
            // We’ll show the full body (it’s text and <=16KB). But we might not have it in memory here.
            // For display we show prefix-only to avoid reading twice; the log file already contains full text.
            var bodyText = DecodeUtf8Lossless(displayPrefix);
            sb.AppendLine(bodyText);
            if ((req.ContentLength ?? 0) > displayPrefix.Length)
                sb.AppendLine("\n[display truncated]");
            return sb.ToString();
        }

        // Binary or >16KB
        sb.AppendLine("[Body logged as .bin: binary and/or >16 KB]");
        sb.AppendLine($"Content-Type: {req.ContentType ?? "unknown"}");
        sb.AppendLine($"Content-Length: {(req.ContentLength?.ToString() ?? "unknown")}");

        if (displayPrefix.Length > 0)
        {
            sb.AppendLine();
            sb.AppendLine("First bytes (base64, truncated):");
            sb.AppendLine(Convert.ToBase64String(displayPrefix));
        }

        return sb.ToString();
    }

    private static string GetBestIp(HttpContext ctx)
    {
        // Prefer X-Forwarded-For if present, otherwise Connection.RemoteIpAddress
        // (Still log the actual socket IP if you want to extend this later.)
        var xff = ctx.Request.Headers["X-Forwarded-For"].ToString();
        if (!string.IsNullOrWhiteSpace(xff))
        {
            var first = xff.Split(',')[0].Trim();
            if (IPAddress.TryParse(first, out _))
                return first;
        }

        var ipAddr = ctx.Connection.RemoteIpAddress;
        if (ipAddr is not null && ipAddr.IsIPv4MappedToIPv6) ipAddr = ipAddr.MapToIPv4();
        return ipAddr?.ToString() ?? "unknown";
    }

    private static bool IsBinaryBody(string? contentType, byte[] sniff)
    {
        // Strong hints from Content-Type
        var ct = (contentType ?? "").ToLowerInvariant();

        if (ct.StartsWith("image/") || ct.StartsWith("audio/") || ct.StartsWith("video/"))
            return true;

        if (ct.Contains("application/octet-stream") ||
            ct.Contains("application/pdf") ||
            ct.Contains("application/zip") ||
            ct.Contains("multipart/form-data"))
            return true;

        // Text-likely types
        var textLikely =
            ct.StartsWith("text/") ||
            ct.Contains("json") ||
            ct.Contains("xml") ||
            ct.Contains("x-www-form-urlencoded") ||
            ct.EndsWith("+json");

        // If no sniff bytes, treat as non-binary
        if (sniff.Length == 0) return false;

        // Heuristic: NUL bytes => binary
        if (sniff.Any(b => b == 0)) return true;

        // If type claims text, try strict UTF-8 decode; if fails => binary
        if (textLikely)
        {
            try
            {
                _ = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true).GetString(sniff);
                return false;
            }
            catch
            {
                return true;
            }
        }

        // Unknown type: decide based on "printability"
        int weird = 0;
        foreach (var b in sniff)
        {
            // allow tab, cr, lf
            if (b == 9 || b == 10 || b == 13) continue;
            if (b >= 32 && b <= 126) continue; // printable ASCII
            weird++;
        }

        // If more than ~15% are non-printable, treat as binary
        return weird > sniff.Length * 0.15;
    }

    private static string DecodeUtf8Lossless(byte[] bytes)
    {
        // Lossless-ish: replacement chars if not valid UTF-8
        return Encoding.UTF8.GetString(bytes);
    }

    private static async Task WriteUtf8Async(Stream s, string text)
    {
        var data = Encoding.UTF8.GetBytes(text);
        await s.WriteAsync(data);
    }

    private static string FsSafeKey(string key)
    {
        // Prevent traversal / weird filesystem names:
        // allow letters, digits, '-', '_', '.'
        Span<char> tmp = stackalloc char[key.Length];
        int n = 0;

        foreach (var ch in key)
        {
            if ((ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') ||
                ch == '-' || ch == '_' || ch == '.')
            {
                tmp[n++] = ch;
            }
            else
            {
                tmp[n++] = '_';
            }

            if (n >= 64) break; // keep dirs sane
        }

        var safe = new string(tmp[..n]).Trim('.');
        return string.IsNullOrWhiteSpace(safe) ? "default" : safe;
    }
}

record LogResult(
    string Id,
    DateTimeOffset TimestampUtc,
    string RemoteIp,
    string SafeKeyForFs,
    string Method,
    string Path,
    string QueryString,
    string? ContentType,
    long? ContentLength,
    bool LoggedAsBinary,
    string AbsoluteLogPath,
    string RelativeLogPath,
    string DisplayText
);


// ===========================
// Discord webhook (embed)
// ===========================

static class DiscordWebhook
{
    public static async Task TrySendAsync(HttpClient http, string webhookUrl, LogResult res, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(webhookUrl) || webhookUrl.Contains("PUT/YOURS/HERE", StringComparison.OrdinalIgnoreCase))
            return;

        // Avoid accidental mentions
        static string Safe(string s) => s.Replace("@", "@\u200b");

        var desc = res.DisplayText;
        if (desc.Length > 3500) desc = desc[..3500] + "\n...[truncated]";

        var payload = new
        {
            embeds = new[]
            {
                new
                {
                    title = "HTTP request logged",
                    description = "```text\n" + Safe(desc) + "\n```",
                    timestamp = res.TimestampUtc.ToString("O"),
                    fields = new[]
                    {
                        new { name = "ID", value = Safe(res.Id), inline = true },
                        new { name = "Key", value = Safe(res.SafeKeyForFs), inline = true },
                        new { name = "IP", value = Safe(res.RemoteIp), inline = true },
                        new { name = "Method", value = Safe(res.Method), inline = true },
                        new { name = "Path", value = Safe(res.Path), inline = false },
                        new { name = "Query", value = Safe(string.IsNullOrEmpty(res.QueryString) ? "(none)" : res.QueryString), inline = false },
                    }
                }
            }
        };

        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

        try
        {
            using var resp = await http.PostAsync(webhookUrl, content, ct);
            // Swallow errors; logging must not break the endpoint
        }
        catch
        {
            // ignored
        }
    }
}


// ===========================
// Asset resolver for /r/{key}
// ===========================

static class AssetResolver
{
    private static readonly FileExtensionContentTypeProvider Mime = new();

    public static bool TryResolve(string assetsRoot, string safeKey, out string? path, out string? contentType)
    {
        path = null;
        contentType = null;

        // 1) Exact match: assets/{key}
        var exact = Path.Combine(assetsRoot, safeKey);
        if (File.Exists(exact))
        {
            path = exact;
            contentType = GuessContentType(exact);
            return true;
        }

        // 2) First match: assets/{key}.*
        var pattern = safeKey + ".*";
        var matches = Directory.EnumerateFiles(assetsRoot, pattern, SearchOption.TopDirectoryOnly)
                               .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
                               .ToList();

        if (matches.Count == 0) return false;

        path = matches[0];
        contentType = GuessContentType(path);
        return true;
    }

    private static string GuessContentType(string filePath)
    {
        if (Mime.TryGetContentType(filePath, out var ct)) return ct;
        return "application/octet-stream";
    }
}


// ===========================
// SkiaSharp PNG renderer
// ===========================

static class PngRenderer
{
    public static byte[] RenderTextToPng(string text)
    {
        // Basic wrapping + dynamic height
        const int padding = 24;
        const int maxWidthPx = 1200;

        using var paint = new SKPaint
        {
            IsAntialias = true,
            Color = SKColors.Black,
            TextSize = 18,
            Typeface = SKTypeface.FromFamilyName("Consolas") ?? SKTypeface.Default
        };

        var lines = WrapText(text.Replace("\r\n", "\n"), paint, maxWidthPx - padding * 2);

        var lineHeight = (int)Math.Ceiling(paint.FontSpacing);
        var width = maxWidthPx;
        var height = padding * 2 + lineHeight * Math.Max(1, lines.Count);

        using var bitmap = new SKBitmap(width, height);
        using var canvas = new SKCanvas(bitmap);
        canvas.Clear(SKColors.White);

        float y = padding + paint.TextSize;
        foreach (var line in lines)
        {
            canvas.DrawText(line, padding, y, paint);
            y += lineHeight;
        }

        using var image = SKImage.FromBitmap(bitmap);
        using var data = image.Encode(SKEncodedImageFormat.Png, 100);
        return data.ToArray();
    }

    private static List<string> WrapText(string text, SKPaint paint, int maxWidth)
    {
        var result = new List<string>();
        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine;
            if (string.IsNullOrEmpty(line))
            {
                result.Add("");
                continue;
            }

            // If it fits, keep it
            if (paint.MeasureText(line) <= maxWidth)
            {
                result.Add(line);
                continue;
            }

            // Word-wrap
            var words = line.Split(' ');
            var current = new StringBuilder();
            foreach (var w in words)
            {
                var candidate = current.Length == 0 ? w : current + " " + w;
                if (paint.MeasureText(candidate) <= maxWidth)
                {
                    if (current.Length > 0) current.Append(' ');
                    current.Append(w);
                }
                else
                {
                    if (current.Length > 0)
                    {
                        result.Add(current.ToString());
                        current.Clear();
                    }

                    // If single "word" is too long, hard-split
                    if (paint.MeasureText(w) <= maxWidth)
                    {
                        current.Append(w);
                    }
                    else
                    {
                        HardSplit(w, paint, maxWidth, result);
                    }
                }
            }

            if (current.Length > 0)
                result.Add(current.ToString());
        }

        return result;
    }

    private static void HardSplit(string s, SKPaint paint, int maxWidth, List<string> outLines)
    {
        var sb = new StringBuilder();
        foreach (var ch in s)
        {
            sb.Append(ch);
            if (paint.MeasureText(sb.ToString()) > maxWidth)
            {
                // push everything except last char
                if (sb.Length > 1)
                {
                    outLines.Add(sb.ToString(0, sb.Length - 1));
                    sb.Clear();
                    sb.Append(ch);
                }
            }
        }
        if (sb.Length > 0) outLines.Add(sb.ToString());
    }
}
