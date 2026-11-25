using System.Text.Json;

namespace SampleSupport;

public static class SampleJson
{
    /// <summary>Options for writing export files.</summary>
    public static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };
}
