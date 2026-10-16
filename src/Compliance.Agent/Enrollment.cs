using System.Net;
using System.Security.Authentication;

namespace Compliance.Agent;

/// <summary>An enrollment refused before asking the server; the message says why, for the person enrolling.</summary>
public sealed class EnrollmentRefusedException(string message) : Exception(message);

public static class EnrollmentFailure
{
    /// <summary>Why an enrollment failed, in words the person at the enrollment window can act on.</summary>
    public static string Describe(Exception e)
    {
        bool Inner<T>()
            where T : Exception
        {
            for (var x = e; x is not null; x = x.InnerException)
                if (x is T)
                    return true;
            return false;
        }
        return e switch
        {
            EnrollmentRefusedException => e.Message,
            AgentApiException { StatusCode: HttpStatusCode.BadRequest } =>
                "管理端拒绝登记：登记码无效、已过期、已撤销或可登记台数已用完。请向管理员索取新的登记码。",
            AgentApiException { StatusCode: HttpStatusCode.TooManyRequests } => "登记请求过于频繁，请过一分钟再试。",
            AgentApiException a => $"管理端返回错误 {(int?)a.StatusCode}，请稍后再试或联系管理员。",
            _ when Inner<AuthenticationException>() =>
                "管理端的 HTTPS 证书不受本机信任。请使用证书上的域名访问（不能用 IP 地址），并确认证书由本机信任的机构签发。",
            HttpRequestException { StatusCode: HttpStatusCode.RequestTimeout } or TaskCanceledException =>
                "连接管理端超时。请确认地址和端口正确、防火墙已放行。",
            HttpRequestException =>
                $"无法连接管理端（{e.Message}）。请确认地址和端口正确、域名能解析到管理端、防火墙已放行。",
            InvalidOperationException when e.Message.Contains("trial mode", StringComparison.Ordinal) =>
                "该地址的管理端不是试用模式，不能用 http:// 连接。正式环境请使用 https:// 地址。",
            InvalidOperationException when e.Message.Contains("HTTP", StringComparison.Ordinal) =>
                "管理端地址须以 https:// 开头，只写域名和端口；试用环境可用 http://内网 IPv4 地址:端口。",
            UriFormatException => "管理端地址格式不正确，例如 https://compliance.example.com。",
            UnauthorizedAccessException => "没有写入客户端数据目录的权限，请以管理员身份登记。",
            _ => $"登记失败：{e.Message}",
        };
    }
}
