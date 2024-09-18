using System.Text.RegularExpressions;

namespace NginxLogAnalyzer;

public abstract partial class Program
{
    static async Task Main(string[] args)
    {
        HashSet<string> ips = new();

        foreach (var file in Directory.GetFiles("c:\\000\\access"))
        {
            using var stream = new StreamReader(file);
            while (!stream.EndOfStream)
            {
                var row = await stream.ReadLineAsync();
                var rec = Parser.Parse(row);
                if (rec is { StatusCode: "200" })
                    ips.Add(rec.Value.RemoteAddress);
            }
        }

        foreach (var ip in ips)
        {
            Console.WriteLine(ip);
        }
    }

    public static partial class Parser
    {
        [GeneratedRegex(
            @"(?<remote_addr>((?:[0-9]{1,3}\.){3}[0-9]{1,3})) (?<dash>\S+) (?<remote_user>\S+) \[(?<time_local>[\w:\/]+\s[+|-]\d{4})\] \""(?<request>\S+)\s?(?<path>\S+)?\s?(?<protocol>\S+)?\"" (?<status_code>\d{3}|-) (?<body_bytes_sent>\d+|-)\s?\""?(?<http_referer>[^\""]*)\""?\s\""?(?<http_user_agent>[^\""]*)\""\s\""?(?<http_x_forwarded_for>[^\""]*)")]
        private static partial Regex RegexParse();

        public static Record? Parse(string value)
        {
            var mc = RegexParse().Matches(value);
            var m = mc.FirstOrDefault();
            if (m != null)
            {
                return new Record
                    {
                        RemoteAddress = m.Groups["remote_addr"].Value,
                        Dash = m.Groups["dash"].Value,
                        RemoteUser = m.Groups["remote_user"].Value,
                        TimeLocal = m.Groups["time_local"].Value,
                        Request = m.Groups["request"].Value,
                        StatusCode = m.Groups["status_code"].Value,
                        BodyBytesSent = m.Groups["body_bytes_sent"].Value,
                        HttpReferer = m.Groups["http_referer"].Value,
                        HttpUserAgent = m.Groups["http_user_agent"].Value,
                        HttpXForwardedFor = m.Groups["http_x_forwarded_for"].Value,
                    };
            }

            return null;
        }
    }

    public record struct Record
    {
        public string RemoteAddress { get; init; }
        public string Dash { get; init; }
        public string RemoteUser { get; init; }
        public string TimeLocal { get; init; }
        public string Request { get; init; }
        public string StatusCode { get; init; }
        public string BodyBytesSent { get; init; }
        public string HttpReferer { get; init; }
        public string HttpUserAgent { get; init; }
        public string HttpXForwardedFor { get; init; }
    }
}