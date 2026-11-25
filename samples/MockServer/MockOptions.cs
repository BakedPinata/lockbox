using System.Globalization;

namespace MockServer;

/// <summary>Settings for the mock server. All credentials here are fake demo values.</summary>
internal sealed class MockOptions
{
    public string Url { get; set; } = "http://localhost:5080";

    public string ApiUsername { get; set; } = "demo";

    public string ApiPassword { get; set; } = "demo-password";

    public string JiraPat { get; set; } = "demo-pat-0000";

    /// <summary>How long issued JWTs are valid. Short by default so that expiry happens during a demo export.</summary>
    public TimeSpan TokenLifetime { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>
    /// When above zero, the signing key is rotated after this many authorised API requests, so tokens that
    /// haven't expired yet start getting 401s. Demonstrates the client's "re-login once and retry" path.
    /// </summary>
    public int InvalidateEvery { get; set; }

    public int RecordCount { get; set; } = 95;

    public int IssueCount { get; set; } = 120;

    public static MockOptions Parse(IReadOnlyList<string> args)
    {
        var options = new MockOptions();
        for (var i = 0; i < args.Count; i++)
        {
            string Value() => i + 1 < args.Count ? args[++i] : throw new ArgumentException($"{args[i]} needs a value.");
            int Int() => int.Parse(Value(), NumberStyles.None, CultureInfo.InvariantCulture);

            switch (args[i])
            {
                case "--url": options.Url = Value(); break;
                case "--api-username": options.ApiUsername = Value(); break;
                case "--api-password": options.ApiPassword = Value(); break;
                case "--jira-pat": options.JiraPat = Value(); break;
                case "--token-lifetime": options.TokenLifetime = TimeSpan.FromSeconds(Int()); break;
                case "--invalidate-every": options.InvalidateEvery = Int(); break;
                case "--records": options.RecordCount = Int(); break;
                case "--issues": options.IssueCount = Int(); break;
                default: throw new ArgumentException($"Unknown option '{args[i]}'.");
            }
        }

        if (options.TokenLifetime <= TimeSpan.Zero)
        {
            throw new ArgumentException("--token-lifetime must be at least 1 second.");
        }

        return options;
    }

    public const string Usage = """
        Usage: MockServer [options]

          --url <url>               Listen address (default http://localhost:5080)
          --api-username <name>     Accepted API username (default demo)
          --api-password <pw>       Accepted API password (default demo-password)
          --jira-pat <token>        Accepted Jira PAT (default demo-pat-0000)
          --token-lifetime <s>      JWT lifetime in seconds (default 20)
          --invalidate-every <n>    Rotate the signing key after every n API requests, forcing 401s (default off)
          --records <n>             Number of API records (default 95)
          --issues <n>              Number of Jira issues (default 120)
        """;
}
