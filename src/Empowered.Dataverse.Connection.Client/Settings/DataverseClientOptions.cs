using System.Diagnostics.CodeAnalysis;
using Empowered.Dataverse.Connection.Store.Contracts;
using Empowered.Dataverse.Connection.Store.Model;

// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

namespace Empowered.Dataverse.Connection.Client.Settings;

public class DataverseClientOptions : IDataverseConnection
{
    public const string Section = "3mpowered:Dataverse";
    
    public DataverseClientOptions()
    {
    }

    [SetsRequiredMembers]
    public DataverseClientOptions(IDataverseConnection connection)
    {
        Name = connection.Name;
        EnvironmentUrl = connection.EnvironmentUrl;
        Type = connection.Type;
        ApplicationId = connection.ApplicationId;
        TenantId = connection.TenantId;
        CertificateFilePath = connection.CertificateFilePath;
        CertificatePassword = connection.CertificatePassword;
        ClientSecret = connection.ClientSecret;
        UserName = connection.UserName;
        Password = connection.Password;
    }

    public required string Name { get; init; }
    public required Uri EnvironmentUrl { get; init; }
    public ConnectionType Type { get; init; }
    public string? ApplicationId { get; init; }
    public string? TenantId { get; init; }
    public string? ClientSecret { get; init; }
    public string? CertificateFilePath { get; init; }
    public string? CertificatePassword { get; init; }
    public string? UserName { get; init; }
    public string? Password { get; init; }
    public IDataverseConnection Clone() => new DataverseConnection(this);
}