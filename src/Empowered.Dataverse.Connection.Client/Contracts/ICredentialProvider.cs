using Azure.Core;
using Empowered.Dataverse.Connection.Store.Contracts;

namespace Empowered.Dataverse.Connection.Client.Contracts;

public interface ICredentialProvider
{
    TokenCredential GetCredential();
}