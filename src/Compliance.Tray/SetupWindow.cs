using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Authentication;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Compliance.Tray;

/// <summary>
/// Enrolls this computer: the management server's address and a one-time code, as an administrator hands them out.
/// The MSI opens it after installing, and the tray offers it while the service waits for an enrollment. The
/// enrollment itself runs the service's executable elevated, since only administrators may write its data directory.
/// </summary>
public sealed partial class SetupWindow : Form
{
    private readonly TextBox server;
    private readonly TextBox code;
    private readonly Label status;
    private readonly Button test;
    private readonly Button enroll;
    private readonly Button close;
    private bool done;

    /// <param name="source">The MSI or folder it was opened from; a 登记配置.json beside it fills in the fields.</param>
    public SetupWindow(string? source)
    {
        int S(int v) => LogicalToDeviceUnits(v);
        Icon = Icons.Window(Icons.App);
        Text = "终端合规 · 登记到管理端";
        Font = Theme.Body;
        ForeColor = Theme.Text;
        BackColor = Theme.Page;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(S(520), S(380));
        StartPosition = FormStartPosition.CenterScreen;

        var header = new Theme.Bar(lineAtTop: false) { Dock = DockStyle.Top, Height = S(69) };
        var logo = new PictureBox
        {
            Image = Icons.Image(Icons.App, S(36)),
            SizeMode = PictureBoxSizeMode.Zoom,
            Bounds = new Rectangle(S(20), S(16), S(36), S(36)),
        };
        var title = Theme.Label("登记到管理端", Theme.Title, Theme.Text);
        title.Location = new Point(S(66), S(13));
        var subtitle = Theme.Label("填写 IT 管理员提供的管理端地址和登记码", Theme.Small, Theme.Muted);
        subtitle.Location = new Point(S(67), S(38));
        header.Controls.AddRange([logo, title, subtitle]);

        var body = new Panel { Dock = DockStyle.Fill, Padding = new Padding(S(24), S(16), S(24), 0) };
        var serverLabel = Theme.Label("管理端地址", Theme.Body, Theme.Text);
        serverLabel.Location = new Point(S(24), S(18));
        server = new TextBox
        {
            Bounds = new Rectangle(S(24), S(42), S(472), S(28)),
            PlaceholderText = "https://compliance.example.com",
        };
        var codeLabel = Theme.Label("登记码", Theme.Body, Theme.Text);
        codeLabel.Location = new Point(S(24), S(82));
        code = new TextBox
        {
            Bounds = new Rectangle(S(24), S(106), S(472), S(28)),
            PlaceholderText = "管理端“终端登记”页生成的 64 位登记码",
        };
        status = new Label
        {
            Bounds = new Rectangle(S(24), S(148), S(472), S(96)),
            Font = Theme.Body,
            ForeColor = Theme.Muted,
            UseMnemonic = false,
            Text = "登记时 Windows 会请求管理员确认。",
        };
        body.Controls.AddRange([serverLabel, server, codeLabel, code, status]);

        var footer = new Theme.Bar(lineAtTop: true) { Dock = DockStyle.Bottom, Height = S(60) };
        test = Plain("测试连接");
        enroll = Plain("登记");
        enroll.BackColor = Theme.Primary;
        enroll.ForeColor = Color.White;
        enroll.FlatAppearance.BorderColor = Theme.Primary;
        close = Plain("关闭");
        footer.Controls.AddRange([test, enroll, close]);
        footer.Layout += (_, _) =>
        {
            var x = footer.Width - S(24);
            foreach (var button in new[] { close, enroll, test })
            {
                x -= button.Width;
                button.Location = new Point(x, (footer.Height - button.Height) / 2);
                x -= S(10);
            }
        };
        Controls.AddRange([body, footer, header]);
        AcceptButton = enroll;
        CancelButton = close;

        test.Click += async (_, _) => await TestAsync();
        enroll.Click += async (_, _) => await EnrollAsync();
        close.Click += (_, _) => Close();
        Prefill(source);
    }

    /// <summary>Raised once the computer is enrolled.</summary>
    public event EventHandler? Enrolled;

    private Button Plain(string text)
    {
        var button = new Button
        {
            Text = text,
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Surface,
            ForeColor = Theme.Text,
            AutoSize = true,
            MinimumSize = new Size(LogicalToDeviceUnits(84), LogicalToDeviceUnits(32)),
            Cursor = Cursors.Hand,
            UseMnemonic = false,
        };
        button.FlatAppearance.BorderColor = Theme.Line;
        return button;
    }

    private void Prefill(string? source)
    {
        if (string.IsNullOrWhiteSpace(source))
            return;
        var folder = Directory.Exists(source) ? source : Path.GetDirectoryName(source);
        var path = folder is null ? null : Path.Combine(folder, "登记配置.json");
        if (path is null || !File.Exists(path))
            return;
        try
        {
            using var json = JsonDocument.Parse(File.ReadAllText(path));
            if (json.RootElement.TryGetProperty("serverUrl", out var url) && url.ValueKind == JsonValueKind.String)
                server.Text = url.GetString();
            if (json.RootElement.TryGetProperty("code", out var c) && c.ValueKind == JsonValueKind.String)
                code.Text = c.GetString();
            Say("已从安装包旁的“登记配置.json”填入，确认后点“登记”。", Theme.Muted);
        }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { }
    }

    private void Say(string text, Color color)
    {
        status.Text = text;
        status.ForeColor = color;
    }

    private void Busy(bool busy)
    {
        test.Enabled = enroll.Enabled = server.Enabled = code.Enabled = !busy;
        UseWaitCursor = busy;
    }

    /// <summary>The address as entered, without a trailing slash; null with the reason shown when it cannot work.</summary>
    private string? Address()
    {
        var text = server.Text.Trim().TrimEnd('/');
        if (
            !Uri.TryCreate(text, UriKind.Absolute, out var uri)
            || uri.Scheme is not ("https" or "http")
            || uri.AbsolutePath != "/"
            || uri.Query.Length > 0
            || uri.Fragment.Length > 0
            || text.Any(ch => char.IsWhiteSpace(ch) || ch == '"')
        )
        {
            Say("管理端地址应以 https:// 开头，只写域名和端口，例如 https://compliance.example.com。", Theme.Danger);
            server.Focus();
            return null;
        }
        return text;
    }

    private async Task<bool> TestAsync()
    {
        if (Address() is not { } url)
            return false;
        Busy(true);
        Say("正在连接管理端…", Theme.Muted);
        try
        {
            // Connects the way the service does: directly, never through a proxy set on this machine (a proxy is
            // what the client checks for, and one could intercept or block its reports). Otherwise a proxy-only
            // network would test fine here while the service never reaches the server.
            using var client = new HttpClient(new HttpClientHandler { UseProxy = false })
            {
                Timeout = TimeSpan.FromSeconds(10),
            };
            using var json = JsonDocument.Parse(await client.GetStringAsync(url + "/api/status"));
            var mode = json.RootElement.TryGetProperty("mode", out var m) ? m.GetString() : null;
            var trial = mode is "LoopbackDemo" or "LanHttpTrial";
            if (url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !trial)
            {
                Say("该管理端不是试用模式，不能用 http:// 连接，请改用 https:// 地址。", Theme.Danger);
                return false;
            }
            Say(trial ? "已连接管理端（试用模式）。" : "已连接管理端。", Theme.Good);
            return true;
        }
        catch (Exception e) when (e is HttpRequestException or TaskCanceledException or JsonException)
        {
            Say(Unreachable(e), Theme.Danger);
            return false;
        }
        finally
        {
            Busy(false);
        }
    }

    private static string Unreachable(Exception e)
    {
        for (var x = e; x is not null; x = x.InnerException)
            if (x is AuthenticationException)
                return "管理端的 HTTPS 证书不受本机信任。请使用证书上的域名访问（不能用 IP 地址），并确认证书由本机信任的机构签发。";
        return e switch
        {
            TaskCanceledException =>
                "连接管理端超时。客户端不经过代理、直接连接管理端，请确认地址和端口正确、防火墙已放行。",
            JsonException => "该地址不是终端合规管理端，请核对地址。",
            HttpRequestException { StatusCode: not null } h => $"该地址返回错误 {(int)h.StatusCode}，请核对地址。",
            _ => $"无法连接管理端（{e.Message}）。请确认地址和端口正确、域名能解析、防火墙已放行。",
        };
    }

    private async Task EnrollAsync()
    {
        if (done)
        {
            Close();
            return;
        }
        if (Address() is not { } url)
            return;
        var key = code.Text.Trim().ToLowerInvariant();
        if (!CodePattern().IsMatch(key))
        {
            Say("登记码应为 64 位，由数字和 a–f 组成，请从管理端完整复制。", Theme.Danger);
            code.Focus();
            return;
        }
        if (!await TestAsync())
            return;
        var agent = Path.Combine(AppContext.BaseDirectory, "Compliance.Agent.exe");
        if (!File.Exists(agent))
        {
            Say("找不到客户端服务程序，请重新安装客户端。", Theme.Danger);
            return;
        }
        var config = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "ComplianceAgent",
            "agent.json"
        );
        var result = Path.Combine(Path.GetTempPath(), $"compliance-enroll-{Guid.NewGuid():N}.txt");
        Busy(true);
        Say("正在登记，请在 Windows 弹出的管理员确认中点“是”…", Theme.Muted);
        try
        {
            // Passed as a list, so each value reaches the elevated process as one argument whatever it holds.
            var start = new ProcessStartInfo(agent)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
            };
            foreach (
                var argument in new[]
                {
                    "--config",
                    config,
                    "--server",
                    url,
                    "--enroll",
                    "--code",
                    key,
                    "--result",
                    result,
                }
            )
                start.ArgumentList.Add(argument);
            using var process = Process.Start(start)!;
            await process.WaitForExitAsync();
            var outcome = File.Exists(result) ? File.ReadAllText(result).Trim() : "";
            if (process.ExitCode == 0)
            {
                done = true;
                Say((outcome.Length > 0 ? outcome : "登记成功。") + "约 1 分钟后管理端显示本机在线。", Theme.Good);
                enroll.Text = "完成";
                test.Visible = close.Visible = false;
                Enrolled?.Invoke(this, EventArgs.Empty);
            }
            else
                Say(outcome.Length > 0 ? outcome : $"登记失败（错误码 {process.ExitCode}）。", Theme.Danger);
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        {
            Say("已取消。登记需要管理员确认，请联系 IT 管理员。", Theme.Danger);
        }
        finally
        {
            try
            {
                File.Delete(result);
            }
            catch (IOException) { }
            Busy(false);
            if (done)
            {
                server.Enabled = code.Enabled = false;
                enroll.Focus();
            }
        }
    }

    [GeneratedRegex("^[0-9a-f]{64}$")]
    private static partial Regex CodePattern();
}
