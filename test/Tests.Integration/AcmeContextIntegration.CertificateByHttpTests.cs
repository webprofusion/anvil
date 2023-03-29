using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme.Resource;
using Certify.ACME.Anvil.Tests;
using Org.BouncyCastle.X509;
using Xunit;
using Xunit.Abstractions;
using static Certify.ACME.Anvil.IntegrationHelper;
using static Certify.ACME.Anvil.Tests.Helper;

namespace Certify.ACME.Anvil
{
    public partial class AcmeContextIntegration
    {
        public class CertificateByHttpTests : AcmeContextIntegration
        {
            public CertificateByHttpTests(ITestOutputHelper output)
                : base(output)
            {
            }

            [Fact]
            public async Task CanGenerateCertificateHttp()
            {
                var dirUri = await GetAcmeUriV2();
                var hosts = new[] { $"www-http-{DomainSuffix}.es256.{Helper.TestDomain1}", $"mail-http-{DomainSuffix}.es256.{Helper.TestDomain2}" };
                var ctx = new AcmeContext(dirUri, GetKeyV2(), http: GetAcmeHttpClient(dirUri));
                var orderCtx = await AuthorizeHttp(ctx, hosts);

                var certKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
                var finalizedOrder = await orderCtx.Finalize(new CsrInfo(), certKey);
                var certChain = await orderCtx.Download(null);

                var pfxBuilder = certChain.ToPfx(certKey);
                pfxBuilder.AddIssuers(IntegrationHelper.TestCertificates);

                var pfx = pfxBuilder.Build("my-pfx", "abcd1234");

                // revoke certificate
                var certParser = new X509CertificateParser();
                var certificate = certParser.ReadCertificate(certChain.Certificate.ToDer());
                var der = certificate.GetEncoded();

                await ctx.RevokeCertificate(der, RevocationReason.Unspecified, null);

                // deactivate authz so the subsequence can trigger challenge validation
                await ClearAuthorizations(orderCtx);
            }
        }
    }
}
