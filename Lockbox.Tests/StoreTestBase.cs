namespace Lockbox.Tests;

public abstract class StoreTestBase : IDisposable
{
    protected const string AppName = "SampleApp";

    private readonly TempDirectory _temp = new();

    protected StoreTestBase() => FilePath = Path.Combine(_temp.Path, "secrets.json");

    protected string Directory => _temp.Path;

    protected string FilePath { get; }

    public void Dispose()
    {
        _temp.Dispose();
        GC.SuppressFinalize(this);
    }

    private protected SecretStore Store(
        AccountInfo? account = null,
        string appName = AppName,
        ISecretProtector? protector = null,
        TimeProvider? time = null,
        string? path = null)
    {
        var who = account ?? Accounts.Owner;
        return new SecretStore(appName, path ?? FilePath, protector ?? new FakeProtector(who), time ?? TimeProvider.System, () => who);
    }

    protected static SecretStoreError ErrorOf(Action action)
    {
        var ex = Assert.ThrowsExactly<SecretStoreException>(action);
        return ex.Error;
    }

    protected void WriteFile(string json) => File.WriteAllText(FilePath, json);
}
