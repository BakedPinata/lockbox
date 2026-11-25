namespace Lockbox.Cli;

/// <summary>A credential that an app needs and that <c>set-credentials</c> prompts for.</summary>
public sealed record CredentialDefinition
{
    /// <summary>Defines a credential.</summary>
    /// <param name="name">The secret name in the store, for example <c>api.password</c>.</param>
    /// <param name="prompt">What to ask the user, for example <c>Password</c>.</param>
    /// <param name="masked">
    /// Whether typing is hidden (shown as <c>*</c>). Use <see langword="false"/> only for values that aren't
    /// sensitive on screen, such as a username. Every value is stored encrypted either way.
    /// </param>
    public CredentialDefinition(string name, string prompt, bool masked = true)
    {
        if (!SecretStore.IsValidSecretName(name))
        {
            throw new ArgumentException($"'{name}' can't be used as a secret name.", nameof(name));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(prompt);
        Name = name;
        Prompt = prompt;
        Masked = masked;
    }

    /// <summary>The secret name in the store.</summary>
    public string Name { get; }

    /// <summary>What to ask the user.</summary>
    public string Prompt { get; }

    /// <summary>Whether typing is hidden.</summary>
    public bool Masked { get; }
}
