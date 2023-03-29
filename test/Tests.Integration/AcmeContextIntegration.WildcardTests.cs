using System.IO;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Pkcs;
using Certify.ACME.Anvil.Tests;
using Xunit;
using Xunit.Abstractions;
using static Certify.ACME.Anvil.IntegrationHelper;
using static Certify.ACME.Anvil.Tests.Helper;

namespace Certify.ACME.Anvil
{
    public partial class AcmeContextIntegration
    {
        public class WildcardTests : AcmeContextIntegration
        {
            public WildcardTests(ITestOutputHelper output)
                : base(output)
            {
            }

            [Fact]
            public async Task CanGenerateWildcard()
            {
                var dirUri = await GetAcmeUriV2();
                var hosts = new[] { $"*.wildcard-{DomainSuffix}.es256.{Helper.TestCI_Domain1}" };
                var ctx = new AcmeContext(dirUri, GetKeyV2(), http: GetAcmeHttpClient(dirUri));

                var orderCtx = await AuthzDns(ctx, hosts);
                var certKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                var finalizedOrder = await orderCtx.Finalize(new CsrInfo
                {
                    CommonName = hosts[0],
                }, certKey);
                var pem = await orderCtx.Download(null);

                var builder = new PfxBuilder(pem.Certificate.ToDer(), certKey);
                foreach (var issuer in pem.Issuers)
                {
                    builder.AddIssuer(issuer.ToDer());
                }

                builder.AddIssuer(File.ReadAllBytes("./Data/test-root.pem"));

                var pfx = builder.Build("ci", "abcd1234");
                Assert.NotNull(pfx);
            }
        }
    }
}
