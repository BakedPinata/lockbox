namespace Lockbox.Setup.WinForms;

internal static class Program
{
    private const string Usage = """
        LockboxSetup [--app <path to app .exe or .dll>] [--secrets-path <path>]

        Saves an app's credentials, encrypted for the Windows account running this tool.
        Run it as the account that will run the app.
        """;

    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();

        string? app = null;
        string? secretsPath = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--app" when i + 1 < args.Length:
                    app = args[++i];
                    break;
                case "--secrets-path" when i + 1 < args.Length:
                    secretsPath = args[++i];
                    break;
                default:
                    // Don't echo the argument: it may be a secret someone tried to pass on the command line.
                    MessageBox.Show(Usage, "Lockbox Setup", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return 2;
            }
        }

        Application.Run(new MainForm(
            app,
            secretsPath,
            new DialogPrompts(),
            description => new SetupSession(description),
            path => new TargetApp(path),
            Environment.ProcessPath ?? "LockboxSetup.exe"));
        return 0;
    }
}
