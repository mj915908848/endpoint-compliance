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
                ]
            ) with
            {
                AdapterNames = ["Mihomo", "Meta Tunnel", "Clash"],
            },
            R("surge", "Surge", "proxy", ["Surge"], ["surge.exe"]),
            R("sing-box", "sing-box", "proxy", ["sing-box"], ["sing-box.exe"]) with
            {
                AdapterNames = ["sing-tun", "singbox"],
            },
            R("shadowsocks", "Shadowsocks", "proxy", ["Shadowsocks"], ["Shadowsocks.exe"]),
            R("hiddify", "Hiddify", "proxy", ["Hiddify"], ["Hiddify.exe", "HiddifyCli.exe"]) with
            {
                AdapterNames = ["Hiddify"],
            },
            R(
                "v2ray",
                "V2Ray / Xray / v2rayN",
                "proxy",
                ["v2rayN", "V2Ray", "Xray", "Nekoray", "Nekobox"],
                ["v2ray.exe", "xray.exe", "v2rayN.exe", "nekoray.exe", "nekobox.exe"]
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
            ),
            R(
                "codex",
                "OpenAI Codex",
                "ai",
                ["Codex", "OpenAI Codex"],
                ["Codex.exe", "codex.exe"],
                ["OpenAI.Codex"],
                ["openai.chatgpt"]
            ),
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
            ),
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
