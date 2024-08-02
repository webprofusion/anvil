using System;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Tests;
using Xunit;
using Xunit.Abstractions;
using static Certify.ACME.Anvil.IntegrationHelper;

namespace Certify.ACME.Anvil
{
    public partial class AcmeContextIntegration
    {
        public class ChangeAccountTests : AcmeContextIntegration
        {
            public ChangeAccountTests(ITestOutputHelper output)
                : base(output)
            {
            }

            [Fact]
            public async Task CanChangeAccountKey()
            {
                var dirUri = await GetAcmeUriV2();

                var ctx = new AcmeContext(dirUri, http: GetAcmeHttpClient(dirUri));
                var account = await ctx.NewAccount(
                    new[] { $"mailto:certes-{DateTime.UtcNow.Ticks}@{Helper.TestCI_Domain1}" }, true);
                var location = await ctx.Account().Location();

                var newKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
                await ctx.ChangeKey(newKey);

                var ctxWithNewKey = new AcmeContext(dirUri, newKey, http: GetAcmeHttpClient(dirUri));
                var locationWithNewKey = await ctxWithNewKey.Account().Location();
                Assert.Equal(location, locationWithNewKey);
            }
        }
    }
}
