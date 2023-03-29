using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;
using Moq;
using Xunit;

namespace Certify.ACME.Anvil
{
    public class IAuthorizationContextExtensionsTests
    {
        [Fact]
        public async Task CanGetTlsAlpnChallenge()
        {
            var ctxMock = new Mock<IAuthorizationContext>(MockBehavior.Strict);
            var challengeMock = new Mock<IChallengeContext>(MockBehavior.Strict);

            challengeMock.SetupGet(m => m.Type).Returns(ChallengeTypes.Dns01);
            ctxMock
                .Setup(m => m.Challenges())
                .ReturnsAsync(new[] { challengeMock.Object });

            Assert.Null(await ctxMock.Object.TlsAlpn());

            challengeMock.SetupGet(m => m.Type).Returns(ChallengeTypes.TlsAlpn01);
            ctxMock
                .Setup(m => m.Challenges())
                .ReturnsAsync(new[] { challengeMock.Object });

            Assert.Equal(challengeMock.Object, await ctxMock.Object.TlsAlpn());
        }
    }
}
