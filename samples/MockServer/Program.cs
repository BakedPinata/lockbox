using MockServer;

if (args.Any(a => a is "--help" or "-h"))
{
    Console.WriteLine(MockOptions.Usage);
    return 0;
}

MockOptions options;
try
{
    options = MockOptions.Parse(args);
}
catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
{
    Console.Error.WriteLine(ex.Message);
    Console.Error.WriteLine(MockOptions.Usage);
    return 2;
}

var mock = MockServerApp.Build(options);
Console.WriteLine($"""
    Lockbox mock server on {options.Url}  (Ctrl+C to stop)

      API:   POST /auth/login, GET /api/records     username "{options.ApiUsername}", password "{options.ApiPassword}"
             tokens last {options.TokenLifetime.TotalSeconds} s{(options.InvalidateEvery > 0 ? $"; signing key rotates every {options.InvalidateEvery} requests" : "")}
      Jira:  GET /rest/api/2/myself, /rest/api/2/search   PAT "{options.JiraPat}"

    These are fake demo credentials. Enter them with each sample's set-credentials command.
    """);
await mock.App.RunAsync();
return 0;
