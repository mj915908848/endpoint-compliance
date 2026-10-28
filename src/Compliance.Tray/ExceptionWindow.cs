using Compliance.Core;

namespace Compliance.Tray;

/// <summary>
/// Asks the administrators for a time-limited exception: a forbidden program found on this computer, or a USB disk
/// the policy restricts. The service sends the request on; the answer comes back as a notice once approved.
/// </summary>
public sealed class ExceptionWindow : Form
{
    private readonly ComboBox item;
    private readonly TextBox reason;
    private readonly NumericUpDown days;
    private readonly Label status;
    private readonly Button submit;
    private ExceptionOption[] options = [];

    public ExceptionWindow()
    {
        int S(int v) => LogicalToDeviceUnits(v);
        Icon = Icons.Window(Icons.App);
        Text = "终端合规 · 申请例外";
        Font = Theme.Body;
        ForeColor = Theme.Text;
        BackColor = Theme.Page;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ClientSize = new Size(S(520), S(420));
        StartPosition = FormStartPosition.CenterScreen;

        var header = new Theme.Bar(lineAtTop: false) { Dock = DockStyle.Top, Height = S(69) };
        var title = Theme.Label("申请例外", Theme.Title, Theme.Text);
        title.Location = new Point(S(24), S(13));
        var subtitle = Theme.Label("向管理员申请临时使用被禁止的软件或 U 盘，批准后自动生效", Theme.Small, Theme.Muted);
        subtitle.Location = new Point(S(25), S(38));
        header.Controls.AddRange([title, subtitle]);

        var body = new Panel { Dock = DockStyle.Fill };
        var itemLabel = Theme.Label("申请项目", Theme.Body, Theme.Text);
        itemLabel.Location = new Point(S(24), S(16));
        item = new ComboBox
        {
            Bounds = new Rectangle(S(24), S(40), S(472), S(28)),
            DropDownStyle = ComboBoxStyle.DropDownList,
        };
        var reasonLabel = Theme.Label("理由", Theme.Body, Theme.Text);
        reasonLabel.Location = new Point(S(24), S(80));
        reason = new TextBox
        {
            Bounds = new Rectangle(S(24), S(104), S(472), S(84)),
            Multiline = true,
            MaxLength = PolicyExceptions.MaxReason,
            PlaceholderText = "说明为什么需要，例如：客户项目需要用 Cursor 调试，预计两周",
        };
        var daysLabel = Theme.Label("需要天数", Theme.Body, Theme.Text);
        daysLabel.Location = new Point(S(24), S(202));
        days = new NumericUpDown
        {
            Bounds = new Rectangle(S(24), S(226), S(100), S(28)),
            Minimum = 1,
            Maximum = PolicyExceptions.MaxDays,
            Value = 7,
        };
        status = new Label
        {
            Bounds = new Rectangle(S(24), S(266), S(472), S(60)),
            Font = Theme.Body,
            ForeColor = Theme.Muted,
            UseMnemonic = false,
            Text = "正在读取……",
        };
        body.Controls.AddRange([itemLabel, item, reasonLabel, reason, daysLabel, days, status]);

        var footer = new Theme.Bar(lineAtTop: true) { Dock = DockStyle.Bottom, Height = S(60) };
        submit = Button("提交申请");
        submit.BackColor = Theme.Primary;
        submit.ForeColor = Color.White;
        submit.FlatAppearance.BorderColor = Theme.Primary;
        submit.Enabled = false;
        var close = Button("关闭");
        footer.Controls.AddRange([submit, close]);
        footer.Layout += (_, _) =>
        {
            var x = footer.Width - S(24);
            foreach (var b in new[] { close, submit })
            {
                x -= b.Width;
                b.Location = new Point(x, (footer.Height - b.Height) / 2);
                x -= S(10);
            }
        };
        Controls.AddRange([body, footer, header]);
        AcceptButton = submit;
        CancelButton = close;
        submit.Click += async (_, _) => await SubmitAsync();
        close.Click += (_, _) => Close();
        Shown += async (_, _) => await LoadAsync();
    }

    private Button Button(string text) =>
        new()
        {
            Text = text,
            FlatStyle = FlatStyle.Flat,
            BackColor = Theme.Surface,
            ForeColor = Theme.Text,
            AutoSize = true,
            MinimumSize = new Size(LogicalToDeviceUnits(84), LogicalToDeviceUnits(32)),
            Cursor = Cursors.Hand,
        };

    private async Task LoadAsync()
    {
        try
        {
            options = await TrayPipe.ExceptionOptionsAsync() ?? [];
        }
        catch (Exception)
        {
            Show("无法连接客户端服务，请稍后再试。", Theme.Danger);
            return;
        }
        item.Items.Clear();
        foreach (var o in options)
            item.Items.Add($"{PolicyExceptions.KindLabel(o.Kind)}：{o.Label}");
        if (options.Length == 0)
        {
            Show("本机目前没有被禁止的软件或被限制的 U 盘，不需要申请例外。", Theme.Muted);
            return;
        }
        item.SelectedIndex = 0;
        submit.Enabled = true;
        Show("提交后由管理员审批；批准后会在通知中心告诉你。", Theme.Muted);
    }

    private async Task SubmitAsync()
    {
        if (item.SelectedIndex < 0)
            return;
        if (reason.Text.Trim().Length == 0)
        {
            Show("请填写理由。", Theme.Danger);
            return;
        }
        var chosen = options[item.SelectedIndex];
        submit.Enabled = false;
        try
        {
            var refused = await TrayPipe.RequestExceptionAsync(
                new(chosen.Kind, chosen.Target, chosen.Label, reason.Text.Trim(), (int)days.Value, "")
            );
            if (refused is null)
            {
                Show("已提交，管理员批准后会在通知中心告诉你。", Theme.Good);
                return;
            }
            Show(refused, Theme.Danger);
        }
        catch (Exception)
        {
            Show("无法连接客户端服务，请稍后再试。", Theme.Danger);
        }
        submit.Enabled = true;
    }

    private void Show(string text, Color color)
    {
        status.Text = text;
        status.ForeColor = color;
    }
}
