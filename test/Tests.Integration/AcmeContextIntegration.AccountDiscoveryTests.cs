using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

using static Certify.ACME.Anvil.Tests.Helper;
using static Certify.ACME.Anvil.IntegrationHelper;

namespace Certify.ACME.Anvil
{
    public partial class AcmeContextIntegration
    {
        public class AccountDiscoveryTests : AcmeContextIntegration
        {
            public AccountDiscoveryTests(ITestOutputHelper output)
                : base(output)
            {
            }

            [Fact]
            public async Task CanDiscoverAccountByKey()
            {
                var dirUri = await GetAcmeUriV2();

                var ctx = new AcmeContext(dirUri, GetKeyV2(), GetAcmeHttpClient(dirUri));
                var acct = await ctx.Account();

                Assert.NotNull(acct.Location);

                var res = await acct.Resource();
            }
        }
    }
}
