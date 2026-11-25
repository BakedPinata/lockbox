using System.Text.Json.Nodes;

namespace Lockbox.Tests;

[TestClass]
public sealed class InspectTests : StoreTestBase
{
    private static readonly string[] Names = ["api.username", "api.password"];

    [TestMethod]
    public void MissingFile()
    {
        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.Missing, status.FileState);
        Assert.IsNull(status.Info);
        Assert.IsNull(status.Error);
        Assert.IsTrue(status.CanSave);
        Assert.IsFalse(status.RequiresReplace);
        Assert.IsTrue(status.Secrets.All(s => s.State == SecretState.Missing));
    }

    [TestMethod]
    public void UsableFileReportsEachSecret()
    {
        var time = new FixedTimeProvider(new DateTimeOffset(2026, 2, 3, 4, 5, 6, TimeSpan.Zero));
        Store(time: time).SetSecret("api.username", "alice");

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.Usable, status.FileState);
        Assert.IsNull(status.Error);
        Assert.AreEqual(new SecretStatus("api.username", SecretState.Usable, time.Now.UtcDateTime, null), status.Secrets[0]);
        Assert.AreEqual(new SecretStatus("api.password", SecretState.Missing, null, null), status.Secrets[1]);
        Assert.AreEqual(Accounts.Owner, status.Info!.EncryptedBy);
    }

    [TestMethod]
    public void UndecryptableEntryIsUnreadable()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["api.username"] = "alice", ["api.password"] = "pw" });
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        root["secrets"]!["api.password"]!["ciphertext"] = root["secrets"]!["api.username"]!["ciphertext"]!.DeepClone();
        WriteFile(root.ToJsonString());

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.Usable, status.FileState);
        Assert.AreEqual(SecretState.Usable, status.Secrets[0].State);
        Assert.AreEqual(SecretState.Unreadable, status.Secrets[1].State);
        Assert.AreEqual(SecretStoreError.DecryptionFailed, status.Secrets[1].Error!.Error);
        Assert.IsNotNull(status.Secrets[1].CreatedUtc);
    }

    [TestMethod]
    public void AnotherAccountsFile()
    {
        Store(Accounts.Other).SetSecret("api.username", "job");

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.OtherAccount, status.FileState);
        Assert.IsTrue(status.RequiresReplace);
        Assert.IsTrue(status.CanSave);
        Assert.AreEqual(SecretStoreError.EncryptedByAnotherAccount, status.Error!.Error);
        Assert.AreEqual(SecretState.Unreadable, status.Secrets[0].State);
        Assert.AreEqual(SecretStoreError.EncryptedByAnotherAccount, status.Secrets[0].Error!.Error);
    }

    [TestMethod]
    public void AnotherAccountsEmptyFileIsUsable()
    {
        Store(Accounts.Other).SetSecret("x", "1");
        Store(Accounts.Other).RemoveSecret("x");

        Assert.AreEqual(SecretFileState.Usable, Store().Inspect(Names).FileState);
    }

    [TestMethod]
    public void AnotherProtectorsFile()
    {
        Store(protector: new FakeProtector(Accounts.Owner, "other")).SetSecret("api.username", "alice");

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.OtherProtector, status.FileState);
        Assert.IsTrue(status.RequiresReplace);
        Assert.AreEqual(SecretStoreError.ProtectorMismatch, status.Error!.Error);
        Assert.AreEqual(SecretState.Unreadable, status.Secrets[0].State);
        Assert.AreEqual(SecretStoreError.ProtectorMismatch, status.Secrets[0].Error!.Error);
    }

    [TestMethod]
    public void CorruptFile()
    {
        WriteFile("{ nope");

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.Corrupt, status.FileState);
        Assert.IsTrue(status.RequiresReplace);
        Assert.IsTrue(status.CanSave);
        Assert.AreEqual(SecretStoreError.CorruptFile, status.Error!.Error);
        Assert.IsTrue(status.Secrets.All(s => s.State == SecretState.Unknown));
    }

    [TestMethod]
    public void NewerFileCannotBeSaved()
    {
        WriteFile("""{"version":2}""");

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.Unsupported, status.FileState);
        Assert.IsFalse(status.CanSave);
        Assert.IsFalse(status.RequiresReplace);
    }

    [TestMethod]
    public void UnreadableFileCannotBeSaved()
    {
        System.IO.Directory.CreateDirectory(FilePath);

        var status = Store().Inspect(Names);

        Assert.AreEqual(SecretFileState.Unreadable, status.FileState);
        Assert.IsFalse(status.CanSave);
        Assert.AreEqual(SecretStoreError.FileAccessFailed, status.Error!.Error);
    }

    [TestMethod]
    public void InvalidNamesAreRejected() =>
        Assert.ThrowsExactly<ArgumentException>(() => Store().Inspect(["bad name"]));
}

[TestClass]
public sealed class ReplaceSecretsTests : StoreTestBase
{
    [TestMethod]
    [DataRow("other-account")]
    [DataRow("other-protector")]
    [DataRow("corrupt")]
    [DataRow("missing")]
    public void ReplacesWhateverWasThere(string existing)
    {
        switch (existing)
        {
            case "other-account":
                Store(Accounts.Other).SetSecrets(new Dictionary<string, string> { ["old.secret"] = "x", ["api.username"] = "job" });
                break;
            case "other-protector":
                Store(protector: new FakeProtector(Accounts.Owner, "other")).SetSecret("old.secret", "x");
                break;
            case "corrupt":
                WriteFile("{ nope");
                break;
        }

        Store().ReplaceSecrets(new Dictionary<string, string> { ["api.username"] = "alice" });

        var info = Store().GetInfo();
        Assert.AreEqual(Accounts.Owner, info.EncryptedBy);
        Assert.AreEqual("fake", info.Protector);
        CollectionAssert.AreEqual(new[] { "api.username" }, info.Secrets.Select(s => s.Name).ToArray());
        Assert.AreEqual("alice", Store().GetSecret("api.username"));
    }

    [TestMethod]
    public void IsAtomic()
    {
        Store().SetSecret("a", "1");

        Store().ReplaceSecrets(new Dictionary<string, string> { ["b"] = "2" });

        CollectionAssert.AreEqual(new[] { FilePath }, System.IO.Directory.GetFiles(Directory));
    }

    [TestMethod]
    public void ValidatesLikeSetSecrets()
    {
        Assert.ThrowsExactly<ArgumentException>(() => Store().ReplaceSecrets(new Dictionary<string, string>()));
        Assert.ThrowsExactly<ArgumentException>(() => Store().ReplaceSecrets(new Dictionary<string, string> { ["a"] = "" }));
        Assert.ThrowsExactly<ArgumentException>(() => Store().ReplaceSecrets(new Dictionary<string, string> { ["bad name"] = "x" }));
        Assert.IsFalse(Store().Exists);
    }
}
