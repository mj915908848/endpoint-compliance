namespace Compliance.Core;

public static class PolicySeed
{
    public static PolicyDocument Create()
    {
        ProductRule R(
            string id,
            string name,
            string category,
            string[] displays,
            string[] exe,
            string[]? packages = null,
            string[]? extensions = null,
            string[]? domains = null
        ) => new(id, name, category, packages ?? [], exe, extensions ?? [], domains ?? []) { DisplayNames = displays };
        var rules = new[]
        {
            R(
                "clash",
                "Clash / Mihomo",
                "proxy",
                [
                    "Clash for Windows",
                    "Clash Verge",
                    "Clash Verge Rev",
                    "Mihomo",
                    "Clash Meta",
                    "FlClash",
                    "Clash Nyanpasu",
                    "Mihomo Party",
                    "GUI.for.Clash",
                ],
                [
                    "clash.exe",
                    "mihomo.exe",
                    "clash-verge.exe",
                    "verge-mihomo.exe",
                    "clash-verge-service.exe",
                    "Clash for Windows.exe",
                    "FlClash.exe",
                    "clash-nyanpasu.exe",
                    "mihomo-party.exe",
                    "GUI.for.Clash.exe",
                ]
            ) with
            {
                AdapterNames = ["Mihomo", "Meta Tunnel", "Clash"],
            },
            R("surge", "Surge", "proxy", ["Surge"], ["surge.exe"]),
            R(
                "sing-box",
                "sing-box / Karing",
                "proxy",
                ["sing-box", "Karing", "GUI.for.SingBox"],
                ["sing-box.exe", "karing.exe", "GUI.for.SingBox.exe"]
            ) with
            {
                AdapterNames = ["sing-tun", "singbox"],
            },
            R(
                "shadowsocks",
                "Shadowsocks / ShadowsocksR",
                "proxy",
                ["Shadowsocks", "ShadowsocksR"],
                ["Shadowsocks.exe", "ShadowsocksR.exe", "ShadowsocksR-dotnet4.0.exe", "ShadowsocksR-dotnet2.0.exe"]
            ),
            R("hiddify", "Hiddify", "proxy", ["Hiddify"], ["Hiddify.exe", "HiddifyCli.exe"]) with
            {
                AdapterNames = ["Hiddify"],
            },
            R(
                "v2ray",
                "V2Ray / Xray / v2rayN",
                "proxy",
                ["v2rayN", "V2Ray", "Xray", "Nekoray", "Nekobox", "Throne", "Qv2ray", "v2rayA"],
                [
                    "v2ray.exe",
                    "xray.exe",
                    "v2rayN.exe",
                    "nekoray.exe",
                    "nekobox.exe",
                    "Throne.exe",
                    "qv2ray.exe",
                    "v2raya.exe",
                ]
            ),
            R("trojan", "Trojan", "proxy", ["Trojan-Qt5", "Trojan"], ["trojan.exe", "trojan-qt5.exe"]),
            R("netch", "Netch", "proxy", ["Netch"], ["Netch.exe"]),
            R(
                "psiphon",
                "Psiphon",
                "proxy",
                ["Psiphon", "Psiphon 3"],
                ["psiphon3.exe"],
                domains: ["psiphon.ca", "psiphon3.com"]
            ),
            R("lantern", "Lantern", "proxy", ["Lantern"], ["lantern.exe"], domains: ["getlantern.org"]),
            R("tor", "Tor Browser", "proxy", ["Tor Browser"], ["tor.exe"], domains: ["torproject.org"]),
            R(
                "outline",
                "Outline",
                "proxy",
                ["Outline", "Outline Client"],
                ["Outline.exe"],
                domains: ["getoutline.org"]
            ),
            R("letsvpn", "快连 LetsVPN", "vpn", ["LetsVPN", "快连", "快连VPN"], ["LetsPRO.exe", "LetsVPN.exe"]),
            R("astrill", "Astrill VPN", "vpn", ["Astrill", "Astrill VPN"], ["astrill.exe"], domains: ["astrill.com"]),
            R(
                "expressvpn",
                "ExpressVPN",
                "vpn",
                ["ExpressVPN"],
                ["ExpressVPN.exe", "expressvpnd.exe", "ExpressVpnService.exe"],
                domains: ["expressvpn.com"]
            ) with
            {
                AdapterNames = ["ExpressVPN"],
            },
            R(
                "nordvpn",
                "NordVPN",
                "vpn",
                ["NordVPN"],
                ["NordVPN.exe", "nordvpn-service.exe"],
                domains: ["nordvpn.com"]
            ) with
            {
                AdapterNames = ["NordLynx", "NordVPN"],
            },
            R(
                "surfshark",
                "Surfshark",
                "vpn",
                ["Surfshark"],
                ["Surfshark.exe", "Surfshark.Service.exe"],
                domains: ["surfshark.com"]
            ) with
            {
                AdapterNames = ["Surfshark"],
            },
            R(
                "protonvpn",
                "Proton VPN",
                "vpn",
                ["Proton VPN", "ProtonVPN"],
                ["ProtonVPN.exe", "ProtonVPN.Client.exe", "ProtonVPNService.exe"],
                domains: ["protonvpn.com"]
            ) with
            {
                AdapterNames = ["ProtonVPN"],
            },
            R(
                "windscribe",
                "Windscribe",
                "vpn",
                ["Windscribe"],
                ["Windscribe.exe", "WindscribeService.exe"],
                domains: ["windscribe.com"]
            ) with
            {
                AdapterNames = ["Windscribe"],
            },
            R(
                "pia",
                "Private Internet Access",
                "vpn",
                ["Private Internet Access"],
                ["pia-client.exe", "pia-service.exe"],
                domains: ["privateinternetaccess.com"]
            ),
            R(
                "cyberghost",
                "CyberGhost VPN",
                "vpn",
                ["CyberGhost", "CyberGhost VPN"],
                ["CyberGhost.exe", "CyberGhost.Service.exe"],
                domains: ["cyberghostvpn.com"]
            ),
            R(
                "mullvad",
                "Mullvad VPN",
                "vpn",
                ["Mullvad VPN"],
                ["Mullvad VPN.exe", "mullvad-daemon.exe"],
                domains: ["mullvad.net"]
            ) with
            {
                AdapterNames = ["Mullvad"],
            },
            R(
                "hotspot-shield",
                "Hotspot Shield",
                "vpn",
                ["Hotspot Shield"],
                ["hsscp.exe", "hsssrv.exe"],
                domains: ["hotspotshield.com"]
            ),
            R(
                "tunnelbear",
                "TunnelBear",
                "vpn",
                ["TunnelBear"],
                ["TunnelBear.exe", "TunnelBear.Maintenance.exe"],
                domains: ["tunnelbear.com"]
            ),
            R(
                "chatgpt",
                "ChatGPT",
                "ai",
                ["ChatGPT"],
                ["ChatGPT.exe"],
                ["OpenAI.ChatGPT", "OpenAI.ChatGPT-Desktop"],
                domains: ["chatgpt.com", "openai.com"]
            ),
            R(
                "claude",
                "Claude / Claude Code",
                "ai",
                ["Claude", "Claude Code"],
                ["Claude.exe", "claude.exe"],
                ["Anthropic.Claude"],
                domains: ["claude.ai", "anthropic.com"]
            ) with
            {
                NpmPackages = ["@anthropic-ai/claude-code"],
            },
            R(
                "codex",
                "OpenAI Codex",
                "ai",
                ["Codex", "OpenAI Codex"],
                ["Codex.exe", "codex.exe"],
                ["OpenAI.Codex"],
                ["openai.chatgpt"]
            ) with
            {
                NpmPackages = ["@openai/codex"],
            },
            R(
                "cursor",
                "Cursor",
                "ai",
                ["Cursor", "Cursor (User)"],
                ["Cursor.exe"],
                domains: ["cursor.com", "cursor.sh"]
            ),
            R(
                "windsurf",
                "Windsurf / Devin Desktop",
                "ai",
                ["Windsurf", "Windsurf (User)", "Devin Desktop"],
                ["Windsurf.exe", "Devin.exe"],
                domains: ["windsurf.com", "codeium.com"]
            ),
            R(
                "antigravity",
                "Google Antigravity",
                "ai",
                ["Antigravity", "Google Antigravity"],
                ["Antigravity.exe"],
                domains: ["antigravity.google"]
            ),
            R("kiro", "Kiro", "ai", ["Kiro", "Kiro (User)"], ["Kiro.exe"], domains: ["kiro.dev"]),
            R("zed", "Zed", "ai", ["Zed"], ["zed.exe"], domains: ["zed.dev"]),
            R(
                "gemini",
                "Gemini",
                "ai",
                ["Gemini"],
                ["gemini.exe"],
                domains: ["gemini.google.com", "aistudio.google.com"]
            ) with
            {
                NpmPackages = ["@google/gemini-cli"],
            },
            R("perplexity", "Perplexity", "ai", ["Perplexity"], ["Perplexity.exe"], domains: ["perplexity.ai"]),
            R("grok", "Grok", "ai", ["Grok"], ["grok.exe"], domains: ["grok.com", "x.ai"]),
            R("poe", "Poe", "ai", ["Poe"], ["poe.exe"], domains: ["poe.com"]),
            R(
                "copilot",
                "GitHub / Microsoft Copilot",
                "ide_ai",
                ["Microsoft Copilot", "GitHub Copilot"],
                ["copilot.exe"],
                ["Microsoft.Copilot"],
                ["github.copilot", "github.copilot-chat"],
                ["githubcopilot.com"]
            ),
            R(
                "jetbrains-ai",
                "JetBrains AI Assistant / Junie",
                "ide_ai",
                ["JetBrains AI Assistant", "Junie"],
                [],
                extensions: ["com.intellij.ml.llm", "org.jetbrains.junie"],
                domains: ["jetbrains.ai", "junie.ai"]
            ),
            R("codeium-extension", "Codeium AI extension", "ide_ai", ["Codeium"], [], extensions: ["codeium.codeium"]),
            R(
                "gemini-code-assist",
                "Gemini Code Assist",
                "ide_ai",
                ["Gemini Code Assist"],
                [],
                extensions: ["google.geminicodeassist"]
            ),
        };
        return new PolicyDocument
        {
            RequiredModules = ["installed", "processes", "proxy", "extensions", "appx", "ports", "users", "cli"],
            Products = rules,
            BlockDomains = rules.SelectMany(r => r.Domains).Distinct().ToArray(),
            // Sangfor aTrust is a common enterprise zero-trust VPN; customers adjust this list to their own.
            ApprovedNetworkAdapters = ["aTrust"],
        };
    }
}
