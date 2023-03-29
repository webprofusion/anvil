using System.Linq;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Jws;
using Certify.ACME.Anvil.Pkcs;
using Certify.ACME.Anvil.Tests;
using Xunit;
using ChallengeTypes = Certify.ACME.Anvil.Acme.Resource.ChallengeTypes;

namespace Certify.ACME.Anvil
{
    public class AcmeClientIntegrationTests
    {
        [Theory]
        [InlineData(KeyAlgorithm.RS256)]
        [InlineData(KeyAlgorithm.ES256)]
        [InlineData(KeyAlgorithm.ES384)]
        public async Task RunAccountFlow(KeyAlgorithm algorithm)
        {
            var dirUri = await IntegrationHelper.GetAcmeUriV1();
            var key = new AccountKey(algorithm);
            using (var client = new AcmeClient(IntegrationHelper.GetAcmeHttpHandler(dirUri)))
            {
                client.Use(key.Export());
                var reg = await client.NewRegistraton();
                reg.Data.Agreement = reg.GetTermsOfServiceUri();

                await client.UpdateRegistration(reg);

                var newKey = new AccountKey().Export();
                await client.ChangeKey(reg, newKey);
                await client.DeleteRegistration(reg);
            }
        }

        [Fact]
        public async Task CanIssueSan()
        {
            var accountKey = await Helper.LoadkeyV1();
            var csr = new CertificationRequestBuilder();
            csr.SubjectAlternativeNames.Add(Helper.TestDomain1);
            csr.SubjectAlternativeNames.Add(Helper.TestDomain1);

            var dirUri = await IntegrationHelper.GetAcmeUriV1();
            using (var client = new AcmeClient(IntegrationHelper.GetAcmeHttpHandler(dirUri)))
            {
                client.Use(accountKey.Export());

                await AuthorizeDns(client, Helper.TestDomain1);
                await AuthorizeDns(client, Helper.TestDomain2);
                await AuthorizeDns(client, Helper.TestDomain3);

                // should returns the valid ID
                var authz = await client.NewAuthorization(new AuthorizationIdentifier
                {
                    Type = AuthorizationIdentifierTypes.Dns,
                    Value = Helper.TestDomain1,
                });

                Assert.Equal(EntityStatus.Valid, authz.Data.Status);

                var authzByLoc = await client.GetAuthorization(authz.Location);
                Assert.Equal(authz.Data.Identifier.Value, authzByLoc.Data.Identifier.Value);

                var cert = await client.NewCertificate(csr);
                var pfx = cert.ToPfx();

                pfx.AddTestCert();

                pfx.Build("my.pfx", "abcd1234");
                await client.RevokeCertificate(cert);
            }
        }

        private static async Task AuthorizeDns(AcmeClient client, string name)
        {
            var authz = await client.NewAuthorization(new AuthorizationIdentifier
            {
                Type = AuthorizationIdentifierTypes.Dns,
                Value = name
            });

            var httpChallengeInfo = authz.Data.Challenges
                .Where(c => c.Type == ChallengeTypes.Http01).First();
            var httpChallenge = await client.CompleteChallenge(httpChallengeInfo);

            while (authz.Data.Status == EntityStatus.Pending)
            {
                // Wait for ACME server to validate the identifier
                await Task.Delay(1000);
                authz = await client.GetAuthorization(httpChallenge.Location);
            }

            Assert.Equal(EntityStatus.Valid, authz.Data.Status);
        }
    }
}
