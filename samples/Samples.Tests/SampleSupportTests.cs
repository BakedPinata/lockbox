using SampleSupport;

namespace Samples.Tests;

[TestClass]
public sealed class SampleSupportTests
{
    [TestMethod]
    [DataRow("https://api.example.com", "https://api.example.com/")]
    [DataRow("https://api.example.com/v2", "https://api.example.com/v2/")]
    [DataRow("https://api.example.com/v2/", "https://api.example.com/v2/")]
    [DataRow("http://localhost:5080", "http://localhost:5080/")]
    [DataRow("http://127.0.0.1:5080/", "http://127.0.0.1:5080/")]
    [DataRow("http://[::1]:5080/", "http://[::1]:5080/")]
    public void AcceptedUrls(string url, string expected) => Assert.AreEqual(expected, ServiceUrl.Parse(url).AbsoluteUri);

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("api.example.com")]
    [DataRow("/relative")]
    [DataRow("http://api.example.com")]
    [DataRow("http://192.168.1.10:5080")]
    [DataRow("ftp://api.example.com")]
    public void RejectedUrls(string? url) => Assert.ThrowsExactly<ArgumentException>(() => ServiceUrl.Parse(url));

    [TestMethod]
    public void PlainHttpToAnotherMachineIsExplained()
    {
        var ex = Assert.ThrowsExactly<ArgumentException>(() => ServiceUrl.Parse("http://jira.internal"));

        Assert.Contains("use https://", ex.Message);
    }

    [TestMethod]
    public void ExportOptionsDefaults()
    {
        var options = ExportOptions.Parse([], "out.json");

        Assert.AreEqual(Path.GetFullPath("out.json"), options.OutputPath);
        Assert.AreEqual(TimeSpan.Zero, options.Delay);
        Assert.IsFalse(options.Verbose);
        Assert.IsEmpty(options.Extra);
    }

    [TestMethod]
    public void ExportOptionsParse()
    {
        var options = ExportOptions.Parse(
            ["--out", "x.json", "--delay-ms", "250", "--verbose", "--secrets-path", "s.json", "--jql", "project = DEMO"],
            "out.json",
            "--jql");

        Assert.AreEqual(Path.GetFullPath("x.json"), options.OutputPath);
        Assert.AreEqual(TimeSpan.FromMilliseconds(250), options.Delay);
        Assert.IsTrue(options.Verbose);
        Assert.AreEqual("project = DEMO", options.Extra["--jql"]);
    }

    [TestMethod]
    public void ExportOptionsAcceptSecretsPathWithEquals() =>
        Assert.AreEqual(Path.GetFullPath("o.json"), ExportOptions.Parse(["--secrets-path=s.json", "--out", "o.json"], "d.json").OutputPath);

    [TestMethod]
    [DataRow("--out")]
    [DataRow("--delay-ms", "soon")]
    [DataRow("--delay-ms", "-5")]
    [DataRow("--out", "--verbose")]
    [DataRow("--jql", "x")]
    public void InvalidExportOptions(params string[] args) =>
        Assert.ThrowsExactly<ArgumentException>(() => ExportOptions.Parse(args, "out.json"));

    [TestMethod]
    public void UnexpectedArgumentsAreNotEchoed()
    {
        var ex = Assert.ThrowsExactly<ArgumentException>(() => ExportOptions.Parse(["--password", "hunter2"], "out.json"));

        Assert.DoesNotContain("hunter2", ex.Message);
        Assert.DoesNotContain("--password", ex.Message);
    }

    [TestMethod]
    public void SettingsLoadFromTheExecutableFolder()
    {
        var name = $"test-{Guid.NewGuid():N}.settings.json";
        var path = Path.Combine(AppContext.BaseDirectory, name);
        File.WriteAllText(path, """
            {
              // comment
              "baseUrl": "https://api.example.com/",
              "SecretsPath": "%TEMP%\\s.json",
            }
            """);
        try
        {
            var settings = SampleSettings.Load(name);

            Assert.AreEqual("https://api.example.com/", settings.BaseUrl);
            Assert.AreEqual(@"%TEMP%\s.json", settings.SecretsPath);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void MissingSettingsAreEmpty() =>
        Assert.AreEqual(new SampleSettings(null, null), SampleSettings.Load($"missing-{Guid.NewGuid():N}.json"));

    [TestMethod]
    public void InvalidSettingsAreReported()
    {
        var name = $"test-{Guid.NewGuid():N}.settings.json";
        var path = Path.Combine(AppContext.BaseDirectory, name);
        File.WriteAllText(path, "{ nope");
        try
        {
            Assert.ThrowsExactly<InvalidDataException>(() => SampleSettings.Load(name));
        }
        finally
        {
            File.Delete(path);
        }
    }

    [TestMethod]
    public void BothSamplesShipASettingsFile()
    {
        Assert.AreEqual("http://localhost:5080/", SampleSettings.Load("ApiExportSample.settings.json").BaseUrl);
        Assert.AreEqual("http://localhost:5080/", SampleSettings.Load("JiraExportSample.settings.json").BaseUrl);
    }
}
