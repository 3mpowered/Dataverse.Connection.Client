namespace Empowered.Dataverse.Connection.Client.Contracts;

public interface ITokenProvider
{
    Task<string> GetToken(string environmentUrl);
}