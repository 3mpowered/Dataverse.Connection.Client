using Microsoft.Xrm.Sdk;

namespace Empowered.Dataverse.Connection.Client.Contracts;

public interface IDataverseClientFactory
{
        TClient Get<TClient>(string? name)
        where TClient : class, IOrganizationService;
}