using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme.Resource;
using Certify.ACME.Anvil.Json;
using Moq;
using Newtonsoft.Json;
using Xunit;

using static Certify.ACME.Anvil.Tests.Helper;

namespace Certify.ACME.Anvil.Acme
{
    public class AcmeHttpClientTests
    {
        private class MockHttpMessageHandler : HttpMessageHandler
        {
            private readonly JsonSerializerSettings jsonSettings = JsonUtil.CreateSettings();

            public bool SendNonce { get; set; } = true;

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                await Task.Yield();

                if (request.RequestUri.AbsoluteUri.EndsWith("directory"))
                {
                    return new HttpResponseMessage(HttpStatusCode.OK)
                    {
                        Content = new StringContent(JsonConvert.SerializeObject(MockDirectoryV2, jsonSettings), Encoding.UTF8, "application/json"),
                    };
                }
                else if (request.RequestUri.AbsoluteUri.EndsWith("newNonce"))
                {
                    var resp = new HttpResponseMessage(HttpStatusCode.OK);
                    if (SendNonce)
                    {
                        resp.Headers.Add("Replay-Nonce", "nonce");
                    }

                    return resp;
                }

                return new HttpResponseMessage(HttpStatusCode.BadRequest);
            }
        }

        [Fact]
        public async Task ThrowWhenNoNonce()
        {
            var dirUri = new Uri("https://acme.d/directory");

            var httpHandler = new MockHttpMessageHandler
            {
                SendNonce = false
            };

            using (var http = new HttpClient(httpHandler))
            {
                var client = new AcmeHttpClient(dirUri, http);
                await Assert.ThrowsAsync<AcmeException>(() => client.ConsumeNonce());
            }
        }

        [Fact]
        public async Task RetryOnBadNonce()
        {
            var accountLoc = new Uri("https://acme.d/acct/1");
            var httpMock = new Mock<IAcmeHttpClient>();
            httpMock.Setup(m => m.Get<Directory>(It.IsAny<Uri>()))
                .ReturnsAsync(new AcmeHttpResponse<Directory>(
                    accountLoc, MockDirectoryV2, null, null));
            httpMock.SetupSequence(
                m => m.Post<Account>(MockDirectoryV2.NewAccount, It.IsAny<object>()))
                .ReturnsAsync(new AcmeHttpResponse<Account>(
                    accountLoc, null, null, new AcmeError
                    {
                        Status = HttpStatusCode.BadRequest,
                        Type = "urn:ietf:params:acme:error:badNonce"
                    }))
                .ReturnsAsync(new AcmeHttpResponse<Account>(
                    accountLoc, new Account
                    {
                        Status = AccountStatus.Valid
                    }, null, null));

            var key = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var ctx = new AcmeContext(
                WellKnownServers.LetsEncryptStagingV2,
                key,
                httpMock.Object);

            await ctx.NewAccount("", true);
            httpMock.Verify(m => m.Post<Account>(MockDirectoryV2.NewAccount, It.IsAny<object>()), Times.Exactly(2));

        }

        [Fact]
        public async Task ThrowOnMultipleBadNonce()
        {
            var accountLoc = new Uri("https://acme.d/acct/1");
            var httpMock = new Mock<IAcmeHttpClient>();
            httpMock.Setup(m => m.Get<Directory>(It.IsAny<Uri>()))
                .ReturnsAsync(new AcmeHttpResponse<Directory>(
                    accountLoc, MockDirectoryV2, null, null));
            httpMock.SetupSequence(
                m => m.Post<Account>(MockDirectoryV2.NewAccount, It.IsAny<object>()))
                .ReturnsAsync(new AcmeHttpResponse<Account>(
                    accountLoc, null, null, new AcmeError
                    {
                        Status = HttpStatusCode.BadRequest,
                        Type = "urn:ietf:params:acme:error:badNonce"
                    }))
                .ReturnsAsync(new AcmeHttpResponse<Account>(
                    accountLoc, null, null, new AcmeError
                    {
                        Status = HttpStatusCode.BadRequest,
                        Type = "urn:ietf:params:acme:error:badNonce"
                    }))
                .ReturnsAsync(new AcmeHttpResponse<Account>(
                    accountLoc, new Account
                    {
                        Status = AccountStatus.Valid
                    }, null, null));

            var key = KeyFactory.NewKey(KeyAlgorithm.RS256);
            var ctx = new AcmeContext(
                WellKnownServers.LetsEncryptStagingV2,
                key,
                httpMock.Object);

            await Assert.ThrowsAsync<AcmeRequestException>(() => ctx.NewAccount("", true));
            httpMock.Verify(m => m.Post<Account>(MockDirectoryV2.NewAccount, It.IsAny<object>()), Times.AtMost(2));
        }


        private class StaticResponseHandler : HttpMessageHandler
        {
            private readonly HttpStatusCode status;
            private readonly string mediaType;
            private readonly string body;

            public StaticResponseHandler(HttpStatusCode status, string mediaType, string body)
            {
                this.status = status;
                this.mediaType = mediaType;
                this.body = body;
            }

            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var resp = new HttpResponseMessage(status) { Content = new ByteArrayContent(Encoding.UTF8.GetBytes(body)) };
                if (mediaType != null)
                {
                    resp.Content.Headers.ContentType = new MediaTypeHeaderValue(mediaType);
                }

                return Task.FromResult(resp);
            }
        }

        [Theory]
        [InlineData(HttpStatusCode.BadGateway, "text/html", "<html><body>502 Bad Gateway</body></html>", "urn:ietf:params:acme:error:serverInternal")]
        [InlineData(HttpStatusCode.GatewayTimeout, null, "", "urn:ietf:params:acme:error:serverInternal")]
        [InlineData(HttpStatusCode.BadRequest, "text/plain", "policy rejected", null)]
        [InlineData(HttpStatusCode.BadRequest, "application/problem+json", "", null)]
        public async Task GeneratesErrorForUnparsableErrorResponse(HttpStatusCode status, string mediaType, string body, string expectedType)
        {
            using (var http = new HttpClient(new StaticResponseHandler(status, mediaType, body)))
            {
                var client = new AcmeHttpClient(new Uri("https://acme.d/directory"), http);
                var resp = await client.Post<Order>(new Uri("https://acme.d/order/1/finalize"), new { });

                Assert.Null(resp.Resource);
                Assert.NotNull(resp.Error);
                Assert.Equal(status, resp.Error.Status);
                Assert.Equal(expectedType, resp.Error.Type);
                Assert.Contains($"HTTP {(int)status}", resp.Error.Detail);
            }
        }

        [Fact]
        public void SetsUserAgent()
        {
            bool IsAnvil(ProductInfoHeaderValue header)
            {
                return header.Product.Name == "Certify.ACME.Anvil"
                    && header.Product.Version == typeof(AcmeHttpClient).GetTypeInfo().Assembly.GetName().Version.ToString();
            }

            Assert.Contains(AcmeHttpClient.CreateHttpClient().DefaultRequestHeaders.UserAgent, IsAnvil);

            var httpClient = new HttpClient();
            var acmeClient = new AcmeHttpClient(new Uri("https://acme.d/directory"), httpClient);

            Assert.Contains(httpClient.DefaultRequestHeaders.UserAgent, IsAnvil);
        }
    }
}
