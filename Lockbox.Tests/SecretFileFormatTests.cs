using System.Text.Json.Nodes;

namespace Lockbox.Tests;

[TestClass]
public sealed class SecretFileFormatTests : StoreTestBase
{
    [TestMethod]
    [DataRow("{ not json", DisplayName = "invalid JSON")]
    [DataRow("", DisplayName = "empty file")]
    [DataRow("[]", DisplayName = "array root")]
    [DataRow("null", DisplayName = "null root")]
    [DataRow("{}", DisplayName = "no version")]
    [DataRow("""{"version":0,"protector":"fake","secrets":{}}""", DisplayName = "version 0")]
    [DataRow("""{"version":"1","protector":"fake","secrets":{}}""", DisplayName = "version as string")]
    [DataRow("""{"version":1,"secrets":{}}""", DisplayName = "no protector")]
    [DataRow("""{"version":1,"protector":"fake"}""", DisplayName = "no secrets")]
    [DataRow("""{"version":1,"protector":"fake","secrets":[]}""", DisplayName = "secrets as array")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"a":null}}""", DisplayName = "null entry")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"a":{"createdUtc":"2026-01-01T00:00:00Z"}}}""", DisplayName = "no ciphertext")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"a":{"ciphertext":"AAAA"}}}""", DisplayName = "no createdUtc")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"a":{"createdUtc":"yesterday","ciphertext":"AAAA"}}}""", DisplayName = "bad date")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"a":{"createdUtc":"2026-01-01T00:00:00Z","ciphertext":"!!!"}}}""", DisplayName = "bad base64")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"a":{"createdUtc":"2026-01-01T00:00:00Z","ciphertext":""}}}""", DisplayName = "empty ciphertext")]
    [DataRow("""{"version":1,"protector":"fake","secrets":{"bad name":{"createdUtc":"2026-01-01T00:00:00Z","ciphertext":"AAAA"}}}""", DisplayName = "invalid secret name")]
    public void CorruptFileIsReported(string json)
    {
        WriteFile(json);

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store().GetSecret("a"));

        Assert.AreEqual(SecretStoreError.CorruptFile, ex.Error);
        Assert.AreEqual(FilePath, ex.FilePath);
        Assert.Contains("Delete it and run set-credentials again", ex.Message);
        Assert.AreEqual(SecretStoreError.CorruptFile, ErrorOf(() => Store().GetInfo()));
    }

    [TestMethod]
    public void CorruptFileIsNotOverwritten()
    {
        WriteFile("{ not json");

        Assert.AreEqual(SecretStoreError.CorruptFile, ErrorOf(() => Store().SetSecret("a", "1")));
        Assert.AreEqual("{ not json", File.ReadAllText(FilePath));
    }

    [TestMethod]
    [DataRow("""{"version":2,"protector":"fake","secrets":{}}""", DisplayName = "version 2")]
    [DataRow("""{"version":99,"secrets":[1,2,3],"somethingNew":true}""", DisplayName = "newer, different shape")]
    public void NewerVersionIsReportedAsUnsupported(string json)
    {
        WriteFile(json);

        var ex = Assert.ThrowsExactly<SecretStoreException>(() => Store().GetSecret("a"));

        Assert.AreEqual(SecretStoreError.UnsupportedVersion, ex.Error);
        Assert.Contains("Update the app", ex.Message);
        Assert.AreEqual(SecretStoreError.UnsupportedVersion, ErrorOf(() => Store().GetInfo()));
    }

    [TestMethod]
    public void NewerVersionIsNotOverwritten()
    {
        const string json = """{"version":2,"protector":"fake","secrets":{}}""";
        WriteFile(json);

        Assert.AreEqual(SecretStoreError.UnsupportedVersion, ErrorOf(() => Store().SetSecret("a", "1")));
        Assert.AreEqual(SecretStoreError.UnsupportedVersion, ErrorOf(() => Store().RemoveSecret("a")));
        Assert.AreEqual(json, File.ReadAllText(FilePath));
    }

    [TestMethod]
    public void UnknownPropertiesAreIgnored()
    {
        Store().SetSecret("a", "1");
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        root["futureSetting"] = "x";
        root["secrets"]!["a"]!["note"] = 42;
        WriteFile(root.ToJsonString());

        Assert.AreEqual("1", Store().GetSecret("a"));
    }

    [TestMethod]
    public void ByteOrderMarkCommentsAndTrailingCommasAreAccepted()
    {
        Store().SetSecret("a", "1");
        var json = File.ReadAllText(FilePath).Replace("\"version\": 1,", "// edited by hand\n  \"version\": 1,", StringComparison.Ordinal);
        File.WriteAllText(FilePath, json.TrimEnd().TrimEnd('}') + ",}", new System.Text.UTF8Encoding(encoderShouldEmitUTF8Identifier: true));

        Assert.AreEqual("1", Store().GetSecret("a"));
    }

    [TestMethod]
    public void IncompleteEncryptedByIsTreatedLeniently()
    {
        Store().SetSecret("a", "1");
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        root["encryptedBy"] = new JsonObject { ["account"] = @"CONTOSO\alice" };
        WriteFile(root.ToJsonString());

        var info = Store().GetInfo();

        Assert.AreEqual(new AccountInfo(@"CONTOSO\alice", null, "(unknown machine)"), info.EncryptedBy);
        Assert.AreEqual("1", Store().GetSecret("a"));
    }

    [TestMethod]
    public void EmptyEncryptedByIsTreatedAsAbsent()
    {
        WriteFile("""{"version":1,"protector":"fake","encryptedBy":{},"secrets":{}}""");

        Assert.IsNull(Store().GetInfo().EncryptedBy);
    }

    [TestMethod]
    public void DatesWithoutAZoneAreReadAsUtc()
    {
        Store().SetSecret("a", "1");
        var root = JsonNode.Parse(File.ReadAllText(FilePath))!;
        root["secrets"]!["a"]!["createdUtc"] = "2026-03-04T05:06:07";
        WriteFile(root.ToJsonString());

        var created = Store().GetInfo().Secrets.Single().CreatedUtc;

        Assert.AreEqual(new DateTime(2026, 3, 4, 5, 6, 7, DateTimeKind.Utc), created);
        Assert.AreEqual(DateTimeKind.Utc, created.Kind);
    }

    [TestMethod]
    public void SecretsAreWrittenInNameOrder()
    {
        Store().SetSecrets(new Dictionary<string, string> { ["c"] = "3", ["a"] = "1", ["b"] = "2" });

        var names = JsonNode.Parse(File.ReadAllText(FilePath))!["secrets"]!.AsObject().Select(kv => kv.Key);

        CollectionAssert.AreEqual(new[] { "a", "b", "c" }, names.ToArray());
    }
}
