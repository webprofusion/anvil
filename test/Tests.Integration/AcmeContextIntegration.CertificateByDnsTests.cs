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
        public class CertificateByDnsTests : AcmeContextIntegration
        {
            public CertificateByDnsTests(ITestOutputHelper output)
                : base(output)
            {
            }

            [Fact]
            public async Task CanGenerateCertificateDns()
            {
                var dirUri = await GetAcmeUriV2();

                var hosts = new[] { $"www-dns-{DomainSuffix}.{Helper.TestDomain1}", $"mail-dns-{DomainSuffix}.es256.{Helper.TestDomain2}" };
                var ctx = new AcmeContext(dirUri, GetKeyV2(), http: GetAcmeHttpClient(dirUri));
                var orderCtx = await AuthzDns(ctx, hosts);
                while (orderCtx == null)
                {
                    Output.WriteLine("DNS authz failed, retrying...");
                    orderCtx = await AuthzDns(ctx, hosts);
                }

                var csr = new CertificationRequestBuilder();
                foreach (var h in hosts)
                {
                    csr.SubjectAlternativeNames.Add(h);
                }

                var der = csr.Generate();

                var finalizedOrder = await orderCtx.Finalize(der);
                var certificate = await orderCtx.Download(null);

                await ClearAuthorizations(orderCtx);
            }
        }

    }
}
