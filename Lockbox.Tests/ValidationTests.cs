namespace Lockbox.Tests;

[TestClass]
public sealed class ValidationTests : StoreTestBase
{
    [TestMethod]
    [DataRow("a")]
    [DataRow("jira.pat")]
    [DataRow("api.password")]
    [DataRow("A1_b-2.c")]
    [DataRow("9lives")]
    public void ValidSecretNames(string name) => Assert.IsTrue(SecretStore.IsValidSecretName(name));

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow(" ")]
    [DataRow(".hidden")]
    [DataRow("-dash")]
    [DataRow("has space")]
    [DataRow("pipe|name")]
    [DataRow("slash/name")]
    [DataRow("ünïcode")]
    public void InvalidSecretNames(string? name) => Assert.IsFalse(SecretStore.IsValidSecretName(name));

    [TestMethod]
    public void SecretNameLengthLimit()
    {
        Assert.IsTrue(SecretStore.IsValidSecretName(new string('a', 128)));
        Assert.IsFalse(SecretStore.IsValidSecretName(new string('a', 129)));
    }

    [TestMethod]
    public void InvalidSecretNamesAreRejectedByEveryOperation()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Store().GetSecret("bad|name"));
        Assert.ThrowsExactly<ArgumentException>(() => Store().SetSecret("bad|name", "1"));
        Assert.ThrowsExactly<ArgumentException>(() => Store().RemoveSecret("bad|name"));
        Assert.ThrowsExactly<ArgumentException>(() => Store().CheckSecrets(["ok", "bad|name"]));
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    public void EmptyValuesAndEmptyBatchesAreRejected()
    {
        var ex = Assert.ThrowsExactly<ArgumentException>(() => Store().SetSecret("a", ""));
        Assert.Contains("'a'", ex.Message);
        Assert.ThrowsExactly<ArgumentException>(() => Store().SetSecrets(new Dictionary<string, string>()));
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow(" ")]
    [DataRow("a|b")]
    [DataRow("a/b")]
    [DataRow(@"a\b")]
    [DataRow(".")]
    [DataRow("..")]
    public void InvalidAppNamesAreRejected(string appName)
    {
        Assert.ThrowsExactly<ArgumentException>(() => new SecretStore(appName, FilePath, new FakeProtector(Accounts.Owner)));
        Assert.ThrowsExactly<ArgumentException>(() => SecretStore.GetDefaultPath(appName));
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("   ")]
    public void NoPathMeansTheDefaultPath(string? path)
    {
        var store = new SecretStore("SampleApp", path, new FakeProtector(Accounts.Owner));

        Assert.AreEqual(SecretStore.GetDefaultPath("SampleApp"), store.FilePath);
    }

    [TestMethod]
    public void DefaultPathIsUnderApplicationData()
    {
        var expected = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SampleApp", "secrets.json");

        Assert.AreEqual(expected, SecretStore.GetDefaultPath("SampleApp"));
    }

    [TestMethod]
    public void EnvironmentVariablesInThePathAreExpanded()
    {
        var variable = "LOCKBOX_TEST_" + Guid.NewGuid().ToString("N");
        Environment.SetEnvironmentVariable(variable, Directory);
        try
        {
            var store = new SecretStore("SampleApp", Path.Combine($"%{variable}%", "custom.json"), new FakeProtector(Accounts.Owner));

            Assert.AreEqual(Path.Combine(Directory, "custom.json"), store.FilePath);
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    [TestMethod]
    public void RelativePathsAreMadeFull()
    {
        var store = new SecretStore("SampleApp", Path.Combine("relative", "secrets.json"), new FakeProtector(Accounts.Owner));

        Assert.AreEqual(Path.GetFullPath(Path.Combine("relative", "secrets.json")), store.FilePath);
        Assert.IsTrue(Path.IsPathFullyQualified(store.FilePath));
    }
}
