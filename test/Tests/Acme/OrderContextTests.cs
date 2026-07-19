using System;
using System.Linq;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme.Resource;
using Certify.ACME.Anvil.Jws;
using Certify.ACME.Anvil.Tests;
using Moq;
using Xunit;

namespace Certify.ACME.Anvil.Acme
{
    public class OrderContextTests
    {
        private static readonly Uri location = new Uri("http://acme.d/order/101");
        private Mock<IAcmeContext> contextMock = new Mock<IAcmeContext>(MockBehavior.Strict);
        private readonly JwsPayload expectedPayload = new JwsSigner(Helper.GetKeyV2()).Sign("", null, location, "nonce");

        private Mock<IAcmeHttpClient> GetHttpClientMock()
        {
            contextMock.Reset();
            
            var httpClientMock = new Mock<IAcmeHttpClient>(MockBehavior.Strict);

            contextMock
                .Setup(c => c.GetDirectory(false))
                .ReturnsAsync(Helper.MockDirectoryV2);
            contextMock
                .SetupGet(c => c.AccountKey)
                .Returns(Helper.GetKeyV2());
            contextMock
                .SetupGet(c => c.BadNonceRetryCount)
                .Returns(1);
            contextMock.SetupGet(c => c.HttpClient).Returns(httpClientMock.Object);
            contextMock
                .Setup(c => c.Sign(It.IsAny<object>(), It.IsAny<Uri>()))
                .Callback((object payload, Uri loc) =>
                {
                    Assert.Null(payload);
                    Assert.Equal(location, loc);
                })
                .ReturnsAsync(expectedPayload);

            return httpClientMock;
        }

        [Fact]
        public async Task CanLoadAuthorizations()
        {
            var order = new Order
            {
                Authorizations = new[]
                {
                    new Uri("http://acme.d/acct/1/authz/1"),
                    new Uri("http://acme.d/acct/1/authz/2"),
                }
            };

            var httpClientMock = GetHttpClientMock();

            httpClientMock
                .Setup(m => m.Post<Order>(location, It.IsAny<JwsPayload>()))
                .Callback((Uri _, object o) =>
                {
                    var p = (JwsPayload)o;
                    Assert.Equal(expectedPayload.Payload, p.Payload);
                    Assert.Equal(expectedPayload.Protected, p.Protected);
                })
                .ReturnsAsync(new AcmeHttpResponse<Order>(location, order, default, default));

            var ctx = new OrderContext(contextMock.Object, location);
            var authzs = await ctx.Authorizations();
            Assert.Equal(order.Authorizations, authzs.Select(a => a.Location));

            // check the context returns empty list instead of null
            httpClientMock
                .Setup(m => m.Post<Order>(location, It.IsAny<JwsPayload>()))
                .ReturnsAsync(new AcmeHttpResponse<Order>(location, new Order(), default, default));
            authzs = await ctx.Authorizations();
            Assert.Empty(authzs);

        }

        [Fact]
        public async Task Download_WithNullOrder_Throws()
        {
            contextMock.Reset();

            var ctx = new OrderContext(contextMock.Object, location);

            await Assert.ThrowsAsync<ArgumentNullException>(async () => await ctx.Download(order: null, preferredChain: null));
        }

        [Fact]
        public async Task Download_WithIncompleteOrder_Throws()
        {
            contextMock.Reset();
            
            var ctx = new OrderContext(contextMock.Object, location);

            await Assert.ThrowsAsync<AcmeException>(async () => await ctx.Download(order: IOrderContextExtensionsTests.BuildOrder(OrderStatus.Processing), preferredChain: null));
        }

        [Fact]
        public async Task Resource_WithRetryAfterInPast_SetsNextRetryToNull()
        {
            var order = new Order
            {
                Status = OrderStatus.Pending
            };

            // Mock with retryAfter in the past (negative value indicates past)
            GetHttpClientMock()
                .Setup(m => m.Post<Order>(location, It.IsAny<JwsPayload>()))
                .ReturnsAsync(new AcmeHttpResponse<Order>(location, order, default, default, retryAfter: -10));

            var ctx = new OrderContext(contextMock.Object, location);
            var result = await ctx.Resource();

            Assert.Equal(order, result);
            Assert.Null(ctx.NextRetry); // Should be null when retryAfter is in the past
        }

        [Fact]
        public async Task Resource_WithRetryAfterInFuture_SetsNextRetry()
        {
            var order = new Order
            {
                Status = OrderStatus.Processing
            };

            // Mock with retryAfter in the future (positive value in seconds)
            var retryAfterSeconds = 30;
            GetHttpClientMock()
                .Setup(m => m.Post<Order>(location, It.IsAny<JwsPayload>()))
                .ReturnsAsync(new AcmeHttpResponse<Order>(location, order, default, default, retryAfter: retryAfterSeconds));

            var beforeCall = DateTime.UtcNow;
            var ctx = new OrderContext(contextMock.Object, location);
            var result = await ctx.Resource();
            var afterCall = DateTime.UtcNow;

            Assert.Equal(order, result);
            Assert.NotNull(ctx.NextRetry);

            // Verify NextRetry is set to approximately retryAfterSeconds in the future
            var expectedRetry = beforeCall.AddSeconds(retryAfterSeconds);
            Assert.True(ctx.NextRetry.Value >= expectedRetry && ctx.NextRetry.Value <= afterCall.AddSeconds(retryAfterSeconds));
        }
    }
}
