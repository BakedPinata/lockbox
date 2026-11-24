using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace Lockbox.Tests;

[TestClass]
public sealed class SecretStoreTests : StoreTestBase
{
    private const string Password = "p@ss wörd ✓";

    [TestMethod]
    public void RoundTripsSeveralSecrets()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = Password });

        Assert.AreEqual("alice", Store().GetSecret("api.username"));
        Assert.AreEqual(Password, Store().GetSecret("api.password"));
    }

    [TestMethod]
    public void FileDoesNotContainPlaintext()
    {
        Store().SetSecret("api.password", Password);

        var json = File.ReadAllText(FilePath);
        Assert.DoesNotContain(Password, json);
        Assert.DoesNotContain("wörd", json);
    }

    [TestMethod]
    public void WritesTheDocumentedFormat()
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 1, 2, 3, 4, 5, TimeSpan.Zero));
        Store(time: time).SetSecret("jira.pat", "token");

        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        Assert.AreEqual(1, (int)root["version"]!);
        Assert.AreEqual("fake", (string)root["protector"]!);
        Assert.AreEqual(Accounts.Owner.Account, (string)root["encryptedBy"]!["account"]!);
        Assert.AreEqual(Accounts.Owner.Sid, (string)root["encryptedBy"]!["sid"]!);
        Assert.AreEqual(Accounts.Owner.Machine, (string)root["encryptedBy"]!["machine"]!);
        Assert.AreEqual("2026-01-02T03:04:05Z", (string)root["secrets"]!["jira.pat"]!["createdUtc"]!);
        Assert.IsFalse(string.IsNullOrEmpty((string)root["secrets"]!["jira.pat"]!["ciphertext"]!));
    }

    [TestMethod]
    public void CreatesMissingFolders()
    {
        var nested = Path.Combine(Directory, "a", "b", "secrets.json");
        Store(path: nested).SetSecret("jira.pat", "token");

        Assert.AreEqual("token", Store(path: nested).GetSecret("jira.pat"));
    }

    [TestMethod]
    public void LeavesNoTemporaryFiles()
    {
        Store().SetSecret("a", "1");
        Store().SetSecret("b", "2");

        CollectionAssert.AreEqual(new[] { FilePath }, System.IO.Directory.GetFiles(Directory));
    }

    [TestMethod]
    public void SettingASecretKeepsTheOthers()
    {
        Store().SetSecret("a", "1");
        Store().SetSecret("b", "2");
        Store().SetSecret("a", "3");

        Assert.AreEqual("3", Store().GetSecret("a"));
        Assert.AreEqual("2", Store().GetSecret("b"));
    }

    [TestMethod]
    public void ReplacingASecretUpdatesItsCreatedDate()
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        Store(time: time).SetSecrets(new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" });
        time.Now = time.Now.AddDays(1);
        Store(time: time).SetSecret("a", "3");

        var created = Store().GetInfo().Secrets.ToDictionary(s => s.Name, s => s.CreatedUtc);
        Assert.AreEqual(new DateTime(2026, 1, 2, 0, 0, 0, DateTimeKind.Utc), created["a"]);
        Assert.AreEqual(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc), created["b"]);
        Assert.AreEqual(DateTimeKind.Utc, created["a"].Kind);
    }

    [TestMethod]
    public void FailedEncryptionLeavesTheFileUnchanged()
    {
        Store().SetSecret("a", "1");
        var before = File.ReadAllText(FilePath);

        var failing = new FailingProtector(Accounts.Owner, failOn: "SampleApp|c");
        Assert.ThrowsExactly<CryptographicException>(
            () => Store(protector: failing).SetSecrets(new Dictionary<string, string> { ["b"] = "2", ["c"] = "3" }));

        Assert.AreEqual(before, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public void MissingFile()
    {
        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store().GetSecret("jira.pat"));

        Assert.AreEqual(SecretStoreError.FileNotFound, ex.Error);
        Assert.AreEqual(FilePath, ex.FilePath);
        Assert.Contains("set-credentials", ex.Message);
        Assert.Contains(Accounts.Owner.Account, ex.Message);
        Assert.IsFalse(Store().Exists);
        Assert.AreEqual(SecretStoreError.FileNotFound, ErrorOf(() => Store().GetInfo()));
        Assert.AreEqual(SecretStoreError.FileNotFound, ErrorOf(() => Store().CheckSecrets(["jira.pat"])));
    }

    [TestMethod]
    public void MissingSecret()
    {
        Store().SetSecret("api.username", "alice");

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store().GetSecret("api.password"));

        Assert.AreEqual(SecretStoreError.SecretNotFound, ex.Error);
        Assert.AreEqual("api.password", ex.SecretName);
    }

    [TestMethod]
    public void WrongEntropyFromAnotherAppNameFails()
    {
        Store().SetSecret("api.password", Password);

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store(appName: "OtherApp").GetSecret("api.password"));

        Assert.AreEqual(SecretStoreError.DecryptionFailed, ex.Error);
        Assert.IsInstanceOfType<CryptographicException>(ex.InnerException);
    }

    [TestMethod]
    public void SwappedEntriesFailToDecrypt()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = Password });

        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        var secrets = root["secrets"]!;
        var user = secrets["api.username"]!["ciphertext"]!.DeepClone();
        secrets["api.username"]!["ciphertext"] = secrets["api.password"]!["ciphertext"]!.DeepClone();
        secrets["api.password"]!["ciphertext"] = user;
        WriteFile(root.ToJsonString());

        Assert.AreEqual(SecretStoreError.DecryptionFailed, ErrorOf(() => Store().GetSecret("api.password")));
        Assert.AreEqual(SecretStoreError.DecryptionFailed, ErrorOf(() => Store().GetSecret("api.username")));
    }

    [TestMethod]
    public void AnotherAccountGetsAnExplanation()
    {
        Store().SetSecret("jira.pat", "token");

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store(Accounts.Other).GetSecret("jira.pat"));

        Assert.AreEqual(SecretStoreError.EncryptedByAnotherAccount, ex.Error);
        Assert.Contains($"encrypted by {Accounts.Owner.Account} on {Accounts.Owner.Machine}", ex.Message);
        Assert.Contains($"you are running as {Accounts.Other.Account} on {Accounts.Other.Machine}", ex.Message);
        Assert.Contains("Re-run set-credentials as the account that will run the app", ex.Message);
    }

    [TestMethod]
    public void SameAccountOnAnotherMachineGetsAnExplanation()
    {
        Store().SetSecret("jira.pat", "token");

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store(Accounts.OwnerElsewhere).GetSecret("jira.pat"));

        Assert.AreEqual(SecretStoreError.EncryptedOnAnotherMachine, ex.Error);
        Assert.Contains(Accounts.Owner.Machine, ex.Message);
        Assert.Contains(Accounts.OwnerElsewhere.Machine, ex.Message);
    }

    [TestMethod]
    public void DecryptionFailureWithoutMetadataIsStillExplained()
    {
        Store().SetSecret("jira.pat", "token");
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!.AsObject();
        root.Remove("encryptedBy");
        WriteFile(root.ToJsonString());

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store(Accounts.Other).GetSecret("jira.pat"));

        Assert.AreEqual(SecretStoreError.DecryptionFailed, ex.Error);
        Assert.Contains("doesn't record which account encrypted it", ex.Message);
    }

    [TestMethod]
    public void AnotherAccountCannotAddToTheFile()
    {
        Store().SetSecret("api.password", Password);
        var before = File.ReadAllText(FilePath);

        Assert.AreEqual(SecretStoreError.EncryptedByAnotherAccount, ErrorOf(() => Store(Accounts.Other).SetSecret("jira.pat", "token")));
        Assert.AreEqual(before, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public void AnotherAccountCanTakeOverAnEmptyFile()
    {
        Store().SetSecret("a", "1");
        Assert.IsTrue(Store().RemoveSecret("a"));

        Store(Accounts.Other).SetSecret("jira.pat", "token");

        Assert.AreEqual("token", Store(Accounts.Other).GetSecret("jira.pat"));
        Assert.AreEqual(Accounts.Other, Store(Accounts.Other).GetInfo().EncryptedBy);
    }

    [TestMethod]
    public void AfterDeleteAnotherAccountCanStartAgain()
    {
        Store().SetSecret("jira.pat", "old");

        Assert.IsTrue(Store(Accounts.Other).Delete());
        Store(Accounts.Other).SetSecret("jira.pat", "new");

        Assert.AreEqual("new", Store(Accounts.Other).GetSecret("jira.pat"));
    }

    [TestMethod]
    public void ProtectorMismatch()
    {
        Store().SetSecret("jira.pat", "token");
        var other = new FakeProtector(Accounts.Owner, id: "other");

        Assert.AreEqual(SecretStoreError.ProtectorMismatch, ErrorOf(() => Store(protector: other).GetSecret("jira.pat")));
        Assert.AreEqual(SecretStoreError.ProtectorMismatch, ErrorOf(() => Store(protector: other).SetSecret("a", "1")));
        Assert.AreEqual("fake", Store(protector: other).GetInfo().Protector);
    }

    [TestMethod]
    public void DecryptedBytesThatAreNotTextAreReportedAsCorrupt()
    {
        Store().SetSecret("jira.pat", "token");

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store(protector: new GarbageProtector(Accounts.Owner)).GetSecret("jira.pat"));

        Assert.AreEqual(SecretStoreError.CorruptFile, ex.Error);
        Assert.AreEqual("jira.pat", ex.SecretName);
    }

    [TestMethod]
    public void CheckSecretsReportsEachSecret()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = Password });
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        root["secrets"]!["api.username"]!["ciphertext"] = root["secrets"]!["api.password"]!["ciphertext"]!.DeepClone();
        WriteFile(root.ToJsonString());

        var results = Store().CheckSecrets(["api.username", "api.password", "jira.pat"]);

        CollectionAssert.AreEqual(new[] { "api.username", "api.password", "jira.pat" }, results.Select(r => r.Name).ToArray());
        Assert.AreEqual(SecretStoreError.DecryptionFailed, results[0].Error?.Error);
        Assert.IsTrue(results[1].Succeeded);
        Assert.AreEqual(SecretStoreError.SecretNotFound, results[2].Error?.Error);
    }

    [TestMethod]
    public void GetInfoDescribesTheFileWithoutDecrypting()
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 5, 6, 7, 8, 9, TimeSpan.Zero));
        Store(time: time).SetSecrets(new Dictionary<string, string> { ["jira.pat"] = "t", ["api.password"] = "p", ["api.username"] = "u" });

        // Another account can read the info even though it can't decrypt.
        var info = Store(Accounts.Other).GetInfo();

        Assert.AreEqual(FilePath, info.FilePath);
        Assert.AreEqual(1, info.Version);
        Assert.AreEqual("fake", info.Protector);
        Assert.AreEqual(Accounts.Owner, info.EncryptedBy);
        CollectionAssert.AreEqual(new[] { "api.password", "api.username", "jira.pat" }, info.Secrets.Select(s => s.Name).ToArray());
        Assert.IsTrue(info.Secrets.All(s => s.CreatedUtc == time.Now.UtcDateTime));
    }

    [TestMethod]
    public void RemoveSecret()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" });

        Assert.IsTrue(Store().RemoveSecret("a"));
        Assert.IsFalse(Store().RemoveSecret("a"));
        Assert.AreEqual(SecretStoreError.SecretNotFound, ErrorOf(() => Store().GetSecret("a")));
        Assert.AreEqual("2", Store().GetSecret("b"));
    }

    [TestMethod]
    public void RemoveSecretKeepsEncryptedBy()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["a"] = "1", ["b"] = "2" });

        Assert.IsTrue(Store(Accounts.Other).RemoveSecret("a"));

        Assert.AreEqual(Accounts.Owner, Store().GetInfo().EncryptedBy);
        Assert.AreEqual("2", Store().GetSecret("b"));
    }

    [TestMethod]
    public void RemoveSecretWithoutAFileReturnsFalse()
    {
        Assert.IsFalse(Store().RemoveSecret("a"));
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    public void Delete()
    {
        Store().SetSecret("a", "1");

        Assert.IsTrue(Store().Exists);
        Assert.IsTrue(Store().Delete());
        Assert.IsFalse(Store().Delete());
        Assert.IsFalse(Store().Exists);
    }

    [TestMethod]
    public void UnreadableFileIsReportedAsAccessFailure()
    {
        // A folder where the file should be can't be read as a file, on any platform.
        System.IO.Directory.CreateDirectory(FilePath);

        Assert.AreEqual(SecretStoreError.FileAccessFailed, ErrorOf(() => Store().GetSecret("a")));
        Assert.AreEqual(SecretStoreError.FileAccessFailed, ErrorOf(() => Store().SetSecret("a", "1")));
    }

    [TestMethod]
    public void UnwritableFolderIsReportedAsAccessFailure()
    {
        // The secrets file's folder would have to be created where a file already exists.
        var blocker = Path.Combine(Directory, "blocker");
        File.WriteAllText(blocker, "");
        var path = Path.Combine(blocker, "secrets.json");

        Assert.AreEqual(SecretStoreError.FileAccessFailed, ErrorOf(() => Store(path: path).SetSecret("a", "1")));
    }

    [TestMethod]
    public void MessagesNeverContainSecretValues()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice-user", ["api.password"] = Password });

        var failures = new List<SecretStoreException>();
        void Capture(Action action) => failures.Add(Assert.ThrowsExactly<SecretStoreException>(action));

        Capture(() => Store(Accounts.Other).GetSecret("api.password"));
        Capture(() => Store(Accounts.OwnerElsewhere).GetSecret("api.password"));
        Capture(() => Store(appName: "OtherApp").GetSecret("api.password"));
        Capture(() => Store(Accounts.Other).SetSecret("api.password", "new-value"));
        Capture(() => Store(protector: new GarbageProtector(Accounts.Owner)).GetSecret("api.password"));
        failures.AddRange(Store(Accounts.Other).CheckSecrets(["api.username", "api.password"]).Select(r => r.Error!));

        foreach (var text in failures.Select(f => f.ToString()))
        {
            Assert.DoesNotContain(Password, text);
            Assert.DoesNotContain("alice-user", text);
            Assert.DoesNotContain("new-value", text);
        }
    }

    private sealed class FailingProtector(AccountInfo account, string failOn) : FakeProtector(account)
    {
        public override byte[] Protect(byte[] plaintext, string context) =>
            context == failOn ? throw new CryptographicException("Simulated failure.") : base.Protect(plaintext, context);
    }

    private sealed class GarbageProtector(AccountInfo account) : FakeProtector(account)
    {
        public override byte[] Unprotect(byte[] ciphertext, string context) => [0xFF, 0xFE, 0xC0];
    }
}
