namespace ApiExportSample.Auth;

/// <summary>The decrypted username and password. Kept in memory only.</summary>
/// <remarks>Deliberately not a record: a record's generated <c>ToString</c> would print the password in logs or a debugger.</remarks>
internal sealed class ApiCredentials(string username, string password)
{
    public string Username { get; } = username;

    public string Password { get; } = password;

    public override string ToString() => $"ApiCredentials {{ Username = {Username}, Password = *** }}";
}
