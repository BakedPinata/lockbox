using System.Security.Cryptography;
using System.Text;

namespace Lockbox.Tests;

internal static class Accounts
{
    public static readonly AccountInfo Owner = new(@"CONTOSO\alice", "S-1-5-21-1000-1001", "PC01");
    public static readonly AccountInfo Other = new(@"CONTOSO\job", "S-1-5-21-1000-2002", "SRV01");
    public static readonly AccountInfo OwnerElsewhere = Owner with { Machine = "SRV01" };
}

/// <summary>
/// Stands in for DPAPI on any platform. Like DPAPI CurrentUser scope, ciphertext only decrypts for
/// the same account (SID) on the same machine, with the same context.
/// </summary>
internal class FakeProtector(AccountInfo account, string id = "fake") : ISecretProtector
{
    public string Id => id;

    public virtual byte[] Protect(byte[] plaintext, string context)
    {
        var key = Key(context);
        return [.. key.AsSpan(0, 4), .. Xor(plaintext, key)];
    }

    public virtual byte[] Unprotect(byte[] ciphertext, string context)
    {
        var key = Key(context);
        if (ciphertext.Length < 4 || !ciphertext.AsSpan(0, 4).SequenceEqual(key.AsSpan(0, 4)))
        {
            throw new CryptographicException("Key not valid for use in specified state.");
        }

        return Xor(ciphertext[4..], key);
    }

    private byte[] Key(string context) =>
        SHA256.HashData(Encoding.UTF8.GetBytes($"{account.Sid}|{account.Machine}|{context}"));

    private static byte[] Xor(byte[] data, byte[] key)
    {
        var result = new byte[data.Length];
        for (var i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }

        return result;
    }
}

internal sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;

    public override DateTimeOffset GetUtcNow() => Now;
}

/// <summary>A unique temporary folder, deleted on dispose.</summary>
internal sealed class TempDirectory : IDisposable
{
    public TempDirectory()
    {
        Path = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "lockbox-tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(Path);
    }

    public string Path { get; }

    public void Dispose()
    {
        try
        {
            Directory.Delete(Path, recursive: true);
        }
        catch (IOException)
        {
            // Best effort.
        }
    }
}
