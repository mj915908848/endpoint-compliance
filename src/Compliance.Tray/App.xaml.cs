using System.IO.Pipes;
using System.IO;
using System.Security.Principal;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using Forms=System.Windows.Forms;

namespace Compliance.Tray;

public partial class App : System.Windows.Application
{
    private Forms.NotifyIcon? icon;
    private Window? window;
    private StackPanel? list;
    private readonly HashSet<string> displayed=[];
    private readonly DispatcherTimer timer=new() { Interval=TimeSpan.FromSeconds(20) };
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ShutdownMode=ShutdownMode.OnExplicitShutdown;
        icon=new Forms.NotifyIcon { Icon=System.Drawing.SystemIcons.Information, Text="终端合规通知", Visible=true };
        var menu=new Forms.ContextMenuStrip();
        menu.Items.Add("查看通知",null,(_,_)=>ShowHistory());
        menu.Items.Add("退出托盘",null,(_,_)=>Shutdown());
        icon.ContextMenuStrip=menu;
        icon.DoubleClick+=(_,_)=>ShowHistory();
        timer.Tick+=async (_,_)=>await RefreshAsync(); timer.Start();
        _=RefreshAsync();
    }
    private void ShowHistory()
    {
        if(window is null)
        {
            list=new StackPanel { Margin=new Thickness(12) };
            var scroll=new ScrollViewer { Content=list,VerticalScrollBarVisibility=ScrollBarVisibility.Auto };
            window=new Window { Title="终端合规通知",Width=520,Height=420,Content=scroll };
            window.Closed+=(_,_)=> { window=null; list=null; };
        }
        window.Show(); window.Activate(); _=RefreshAsync();
    }
    private async Task RefreshAsync()
    {
        try
        {
            var notices=await PipeRequestAsync("{\"action\":\"list\"}");
            using var json=JsonDocument.Parse(notices);
            if(json.RootElement.ValueKind!=JsonValueKind.Array) return;
            list?.Children.Clear();
            foreach(var notice in json.RootElement.EnumerateArray())
            {
                var id=notice.GetProperty("eventId").GetString()!;
                var message=notice.GetProperty("message").GetString()??"";
                bool acknowledged=notice.GetProperty("acknowledged").GetBoolean();
                if(!acknowledged && displayed.Add(id)) icon?.ShowBalloonTip(5000,"终端合规通知",message[..Math.Min(message.Length,200)],Forms.ToolTipIcon.Warning);
                if(list is null) continue;
                var row=new StackPanel { Margin=new Thickness(0,0,0,12) };
                row.Children.Add(new TextBlock { Text=message,TextWrapping=TextWrapping.Wrap });
                if(!acknowledged)
                {
                    var button=new System.Windows.Controls.Button { Content="标为已读",Tag=id,HorizontalAlignment=System.Windows.HorizontalAlignment.Left };
                    button.Click+=async (_,_)=> { await PipeRequestAsync(JsonSerializer.Serialize(new { action="ack",eventId=id })); await RefreshAsync(); };
                    row.Children.Add(button);
                }
                list.Children.Add(row);
            }
        }
        catch(Exception ex) when(ex is IOException or TimeoutException or JsonException)
        { if(list is not null) { list.Children.Clear(); list.Children.Add(new TextBlock { Text="服务通知不可用；稍后自动重试。" }); } }
    }
    private static async Task<string> PipeRequestAsync(string request)
    {
        using var pipe=new NamedPipeClientStream(".","ComplianceAgent.Notifications.v1",PipeDirection.InOut,PipeOptions.Asynchronous,TokenImpersonationLevel.Identification);
        await pipe.ConnectAsync(2000);
        using var writer=new StreamWriter(pipe,leaveOpen:true) { AutoFlush=true };
        using var reader=new StreamReader(pipe,leaveOpen:true);
        await writer.WriteLineAsync(request);
        return await reader.ReadLineAsync()??throw new IOException("Empty service response");
    }
    protected override void OnExit(ExitEventArgs e) { timer.Stop(); if(icon is not null) { icon.Visible=false; icon.Dispose(); } base.OnExit(e); }
}
