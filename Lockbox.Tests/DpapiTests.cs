using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json.Nodes;

namespace Lockbox.Tests;

/// <summary>Tests against real Windows DPAPI. Skipped on other platforms.</summary>
[TestClass]
[OSCondition(OperatingSystems.Windows)]
public sealed class DpapiTests : IDisposable
{
    private readonly TempDirectory _temp = new();
    private readonly DpapiUserProtector _protector = new();

    public void Dispose() => _temp.Dispose();

    [TestMethod]
    public void RoundTrips()
    {
        var plaintext = Encoding.UTF8.GetBytes("p@ss wörd ✓");

        var ciphertext = _protector.Protect(plaintext, "SampleApp|api.password");

        CollectionAssert.AreEqual(plaintext, _protector.Unprotect(ciphertext, "SampleApp|api.password"));
    }

    [TestMethod]
    public void CiphertextIsNotThePlaintextAndDiffersEachTime()
    {
        var plaintext = Encoding.UTF8.GetBytes("secret-value");

        var first = _protector.Protect(plaintext, "ctx");
        var second = _protector.Protect(plaintext, "ctx");

        Assert.AreEqual(-1, first.AsSpan().IndexOf(plaintext));
        CollectionAssert.AreNotEqual(first, second);
    }

    [TestMethod]
    public void WrongEntropyFails()
    {
        var ciphertext = _protector.Protect([1, 2, 3], "SampleApp|api.password");

        Assert.Throws<CryptographicException>(() => _protector.Unprotect(ciphertext, "SampleApp|api.username"));
        Assert.Throws<CryptographicException>(() => _protector.Unprotect(ciphertext, "OtherApp|api.password"));
    }

    [TestMethod]
    public void TamperedCiphertextFails()
    {
        var ciphertext = _protector.Protect([1, 2, 3], "ctx");
        ciphertext[^1] ^= 0xFF;

        Assert.Throws<CryptographicException>(() => _protector.Unprotect(ciphertext, "ctx"));
    }

    [TestMethod]
    public void SecretStoreEndToEnd()
    {
        var path = Path.Combine(_temp.Path, "secrets.json");
        var store = new SecretStore("LockboxTests", path);
        store.SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = "p@ss" });

        Assert.AreEqual("alice", store.GetSecret("api.username"));
        Assert.AreEqual("p@ss", store.GetSecret("api.password"));
        Assert.IsTrue(store.CheckSecrets(["api.username", "api.password"]).All(r => r.Succeeded));

        var info = store.GetInfo();
        using var identity = WindowsIdentity.GetCurrent();
        Assert.AreEqual(DpapiUserProtector.ProtectorId, info.Protector);
        Assert.AreEqual(identity.User!.Value, info.EncryptedBy!.Sid);
        Assert.AreEqual(identity.Name, info.EncryptedBy.Account);
        Assert.AreEqual(Environment.MachineName, info.EncryptedBy.Machine);
    }

    [TestMethod]
    public void SecretStoreSwappedEntriesFail()
    {
        var path = Path.Combine(_temp.Path, "secrets.json");
        var store = new SecretStore("LockboxTests", path);
        store.SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = "p@ss" });

        var root = JsonNode.Parse(File.ReadAllText(path))!;
        root["secrets"]!["api.username"]!["ciphertext"] = root["secrets"]!["api.password"]!["ciphertext"]!.DeepClone();
        File.WriteAllText(path, root.ToJsonString());

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => store.GetSecret("api.username"));
        Assert.AreEqual(SecretStoreError.DecryptionFailed, ex.Error);
    }

    [TestMethod]
    public void SecretStoreWithAnotherAppNameFails()
    {
        var path = Path.Combine(_temp.Path, "secrets.json");
        new SecretStore("LockboxTests", path).SetSecret("jira.pat", "token");

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => new SecretStore("OtherApp", path).GetSecret("jira.pat"));
        Assert.AreEqual(SecretStoreError.DecryptionFailed, ex.Error);
    }
}

[TestClass]
[OSCondition(ConditionMode.Exclude, OperatingSystems.Windows)]
public sealed class DpapiUnsupportedPlatformTests
{
    [TestMethod]
    public void DpapiIsNotAvailableOffWindows() =>
        Assert.Throws<PlatformNotSupportedException>(() => new DpapiUserProtector().Protect([1], "ctx"));
}
