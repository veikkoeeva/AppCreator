using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading.Tasks;
using System.Linq;

namespace AppCreator
{
    public class RbacAssignement
    {
        public RbacAssignmentProperties properties { get; set; }
        public string id { get; set; }
        public string type { get; set; }
        public string name { get; set; }
    }

    public class RbacAssignmentProperties
    {
        public string roleDefinitionId { get; set; }
        public string principalId { get; set; }
        public string scope { get; set; }
        public DateTime createdOn { get; set; }
        public DateTime updatedOn { get; set; }
        public object createdBy { get; set; }
        public string updatedBy { get; set; }
    }



    public class PrincipalCreation
    {
        public string odatametadata { get; set; }
        public string odatatype { get; set; }
        public string objectType { get; set; }
        public string objectId { get; set; }
        public object deletionTimestamp { get; set; }
        public bool accountEnabled { get; set; }
        public object[] addIns { get; set; }
        public object[] alternativeNames { get; set; }
        public string appDisplayName { get; set; }
        public string appId { get; set; }
        public string appOwnerTenantId { get; set; }
        public bool appRoleAssignmentRequired { get; set; }
        public object[] appRoles { get; set; }
        public string displayName { get; set; }
        public object errorUrl { get; set; }
        public string homepage { get; set; }
        public object[] keyCredentials { get; set; }
        public object logoutUrl { get; set; }
        public Oauth2permissions[] oauth2Permissions { get; set; }
        public object[] passwordCredentials { get; set; }
        public object preferredTokenSigningKeyThumbprint { get; set; }
        public string publisherName { get; set; }
        public object[] replyUrls { get; set; }
        public object samlMetadataUrl { get; set; }
        public string[] servicePrincipalNames { get; set; }
        public string servicePrincipalType { get; set; }
        public object[] tags { get; set; }
        public object tokenEncryptionKeyId { get; set; }
    }

    public class Oauth2permissions
    {
        public string adminConsentDescription { get; set; }
        public string adminConsentDisplayName { get; set; }
        public string id { get; set; }
        public bool isEnabled { get; set; }
        public string type { get; set; }
        public string userConsentDescription { get; set; }
        public string userConsentDisplayName { get; set; }
        public string value { get; set; }
    }



    public class ApplicationCreation
    {
        public string odatametadata { get; set; }
        public string odatatype { get; set; }
        public string objectType { get; set; }
        public string objectId { get; set; }
        public object deletionTimestamp { get; set; }
        public object acceptMappedClaims { get; set; }
        public object[] addIns { get; set; }
        public string appId { get; set; }
        public object[] appRoles { get; set; }
        public bool availableToOtherTenants { get; set; }
        public string displayName { get; set; }
        public object errorUrl { get; set; }
        public object groupMembershipClaims { get; set; }
        public string homepage { get; set; }
        public string[] identifierUris { get; set; }
        public object[] keyCredentials { get; set; }
        public object[] knownClientApplications { get; set; }
        public object logoutUrl { get; set; }
        public bool oauth2AllowImplicitFlow { get; set; }
        public bool oauth2AllowUrlPathMatching { get; set; }
        public Oauth2permissions[] oauth2Permissions { get; set; }
        public bool oauth2RequirePostResponse { get; set; }
        public object optionalClaims { get; set; }
        public object[] passwordCredentials { get; set; }
        public object publicClient { get; set; }
        public object recordConsentConditions { get; set; }
        public object[] replyUrls { get; set; }
        public object[] requiredResourceAccess { get; set; }
        public object samlMetadataUrl { get; set; }
        public object tokenEncryptionKeyId { get; set; }
    }


    public class Applications
    {
        public string odatametadata { get; set; }
        public Application[] value { get; set; }
    }

    public class Application
    {
        public string odatatype { get; set; }
        public string objectType { get; set; }
        public string objectId { get; set; }
        public object deletionTimestamp { get; set; }
        public object acceptMappedClaims { get; set; }
        public object[] addIns { get; set; }
        public string appId { get; set; }
        public object[] appRoles { get; set; }
        public bool availableToOtherTenants { get; set; }
        public string displayName { get; set; }
        public object errorUrl { get; set; }
        public object groupMembershipClaims { get; set; }
        public string homepage { get; set; }
        public string[] identifierUris { get; set; }
        public Keycredential[] keyCredentials { get; set; }
        public object[] knownClientApplications { get; set; }
        public object logoutUrl { get; set; }
        public bool oauth2AllowImplicitFlow { get; set; }
        public bool oauth2AllowUrlPathMatching { get; set; }
        public Oauth2permissions[] oauth2Permissions { get; set; }
        public bool oauth2RequirePostResponse { get; set; }
        public object optionalClaims { get; set; }
        public object[] passwordCredentials { get; set; }
        public object publicClient { get; set; }
        public object recordConsentConditions { get; set; }
        public object[] replyUrls { get; set; }
        public object[] requiredResourceAccess { get; set; }
        public object samlMetadataUrl { get; set; }
        public object tokenEncryptionKeyId { get; set; }
    }

    public class Keycredential
    {
        public object customKeyIdentifier { get; set; }
        public DateTime endDate { get; set; }
        public string keyId { get; set; }
        public DateTime startDate { get; set; }
        public string type { get; set; }
        public string usage { get; set; }
        public object value { get; set; }
    }


    public class Tenants
    {
        public Tenant[] value { get; set; }
    }

    public class Tenant
    {
        public string id { get; set; }
        public string tenantId { get; set; }
    }

    public class Subscriptions
    {
        public Subscription[] value { get; set; }
    }

    public class Subscription
    {
        public string id { get; set; }
        public string subscriptionId { get; set; }
        public string displayName { get; set; }
        public string state { get; set; }
        public Subscriptionpolicies subscriptionPolicies { get; set; }
        public string authorizationSource { get; set; }
    }

    public class Subscriptionpolicies
    {
        public string locationPlacementId { get; set; }
        public string quotaId { get; set; }
        public string spendingLimit { get; set; }
    }

    public class AzureToken
    {
        public string token_type { get; set; }
        public string scope { get; set; }
        public string expires_in { get; set; }
        public string ext_expires_in { get; set; }
        public string expires_on { get; set; }
        public string not_before { get; set; }
        public string resource { get; set; }
        public string access_token { get; set; }
        public string refresh_token { get; set; }
    }

    public static class Program
    {
        public static void Main()
        {
            MainAsync().GetAwaiter().GetResult();
        }


        public static async Task<AzureToken> GetAccessToken(string userName, string password, Uri resource)
        {
            //https://stackoverflow.com/questions/30454771/how-does-azure-powershell-work-with-username-password-based-auth
            const string ClientId = "1950a258-227b-4e31-a9cf-717495945fc2";
            using(var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                string tokenEndpoint = "https://login.microsoftonline.com/common/oauth2/token";
                var body = $"resource={resource}&client_id={ClientId}&grant_type=password&username={userName}&password={password}";
                var stringContent = new StringContent(body, Encoding.UTF8, "application/x-www-form-urlencoded");
                var response = await client.PostAsync(tokenEndpoint, stringContent).ConfigureAwait(false);
                var result = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

                return JsonConvert.DeserializeObject<AzureToken>(result);
            }
        }


        public static async Task MainAsync()
        {
            Uri managementResource = new Uri("https://management.core.windows.net/");
            Uri graphResource = new Uri("https://graph.microsoft.com/");
            Uri windowsResource = new Uri("https://graph.windows.net/");
            Uri azureManagementResource = new Uri("https://management.azure.com/");

            //https://stackoverflow.com/questions/30454771/how-does-azure-powershell-work-with-username-password-based-auth
            const string UserName = "<INSERT USERNAME HERE>";
            const string Password = "<INSERT PASSWORD HERE>";
            const string IdentifierUri = "https://test.com/testapp";

            //https://stackoverflow.com/questions/44619481/login-azurermaccount-and-related-equivalents-in-net-azure-sdk?noredirect=1&lq=1
            //The latest subscription API version: https://docs.microsoft.com/en-us/rest/api/resources/subscriptions.
            string apiVersion = "2016-06-01";

            var managementToken = await GetAccessToken(UserName, Password, managementResource).ConfigureAwait(false);
            using(var client = new HttpClient())
            {
                client.DefaultRequestHeaders.Add("Authorization", $"bearer {managementToken.access_token}");
                var subcriptions = JsonConvert.DeserializeObject<Subscriptions>(await client.GetStringAsync($"https://management.azure.com/subscriptions?api-version={apiVersion}").ConfigureAwait(false));
                var tenants = JsonConvert.DeserializeObject<Tenants>(await client.GetStringAsync($"https://management.azure.com/tenants?api-version={apiVersion}").ConfigureAwait(false));
                
                string subscriptionId = subcriptions.value[0].subscriptionId;
                string tenantId = tenants.value[0].tenantId;

                //This is, or should be, from roles. Let's assume for the purposes of this demo it's a constant value.                
                var roles = await (await client.GetAsync($"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions?$filter=roleName%20eq%20'Owner'&api-version=2015-07-01").ConfigureAwait(false)).Content.ReadAsStringAsync().ConfigureAwait(false);
                var roleDefinitionId = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635";

                client.DefaultRequestHeaders.Clear();
                var windowsToken = await GetAccessToken(UserName, Password, windowsResource).ConfigureAwait(false);
                client.DefaultRequestHeaders.Add("Authorization", $"bearer {windowsToken.access_token}");

                var appResponseContent = await client.GetAsync($"https://graph.windows.net/{tenants.value[0].tenantId}/applications?api-version=1.6").ConfigureAwait(false);
                var applications = JsonConvert.DeserializeObject<Applications>(await appResponseContent.Content.ReadAsStringAsync().ConfigureAwait(false));
                
                if(applications.value == null || !applications.value.SelectMany(i => i.identifierUris).Any(i => i.Equals(IdentifierUri)))
                {
                    string appCreation = $"{{ \"displayName\":\"Test app\", \"identifierUris\": [\"{IdentifierUri}\"],\"homePage\":\"http://localhost\"}}";
                    var appCreationContent = new StringContent(appCreation, Encoding.UTF8, "application/json");
                    var newAppResponse = await client.PostAsync($"https://graph.windows.net/{tenantId}/applications?api-version=1.6", appCreationContent).ConfigureAwait(false);
                    newAppResponse.EnsureSuccessStatusCode();
                    var createdApplication = JsonConvert.DeserializeObject<ApplicationCreation>(await newAppResponse.Content.ReadAsStringAsync().ConfigureAwait(false));
                    var applicationId = createdApplication.appId;

                    var principalAssignment = $"{{\"appId\":\"{createdApplication.appId}\"}}";
                    var principalAssignementContent = new StringContent(principalAssignment, Encoding.UTF8, "application/json");
                    var principalAssignementResponse = await client.PostAsync($"https://graph.windows.net/{tenantId}/servicePrincipals?api-version=1.6", principalAssignementContent).ConfigureAwait(false);
                    principalAssignementResponse.EnsureSuccessStatusCode();
                    var principal = JsonConvert.DeserializeObject<PrincipalCreation>(await principalAssignementResponse.Content.ReadAsStringAsync().ConfigureAwait(false));

                    //The principal creation might take some time to propagate through the right places...
                    await Task.Delay(TimeSpan.FromSeconds(30)).ConfigureAwait(false);

                    //This doesn't seem to have value...
                    var applicationServicePrincipal = await (await client.GetAsync($"https://graph.windows.net/{tenantId}/servicePrincipals?$filter=servicePrincipalNames/any(c:%20c%20eq%20'applicationID')&api-version=1.6").ConfigureAwait(false)).Content.ReadAsStringAsync().ConfigureAwait(false);

                    //How to do basically "New-AzureRmRoleAssignment -RoleDefinitionName Owner -ServicePrincipalName $adApp.ApplicationId.Guid"
                    var azureManagementToken = await GetAccessToken(UserName, Password, azureManagementResource).ConfigureAwait(false);
                    client.DefaultRequestHeaders.Clear();
                    client.DefaultRequestHeaders.Add("Authorization", $"bearer {azureManagementToken.access_token}");
                    var roleAssignment = $"{{\"properties\": {{\"roleDefinitionId\": \"/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleDefinitions/{roleDefinitionId}\", \"principalId\": \"{principal.objectId}\"}}}}";
                    var roleAssignementContent = new StringContent(roleAssignment, Encoding.UTF8, "application/json");
                    var roleAssignementUrl = $"https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Authorization/roleAssignments/{Guid.NewGuid().ToString()}?api-version=2015-07-01";
                    var roleAssignmentResponseContent = await client.PutAsync(roleAssignementUrl, roleAssignementContent).ConfigureAwait(false);
                    var roleAssignmentResponse = await roleAssignmentResponseContent.Content.ReadAsStringAsync().ConfigureAwait(false);
                    var roleAssignement = JsonConvert.DeserializeObject<RbacAssignement>(roleAssignmentResponse);
                }

                var deleteResponseContent = await client.DeleteAsync($"https://graph.windows.net/{tenants.value[0].tenantId}/applications/{applications.value[0].appId}?api-version=1.6").ConfigureAwait(false);
                var deleteResponseString = await deleteResponseContent.Content.ReadAsStringAsync().ConfigureAwait(false);
            }
        }
    }
}