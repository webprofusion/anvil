using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;
using Moq;
using Xunit;

namespace Certify.ACME.Anvil
{
    public class IAccountContextExtensionsTests
    {
        [Fact]
        public async Task CanDeactivateAccount()
        {
            var ctx = new Mock<IAccountContext>();

            var tsk = Task.FromResult(ctx.Object);
            await tsk.Deactivate();
            ctx.Verify(m => m.Deactivate(), Times.Once);
        }
    }
}
