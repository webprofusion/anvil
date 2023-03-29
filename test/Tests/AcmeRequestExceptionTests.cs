using Xunit;

#if !NETCOREAPP1_0
#endif

namespace Certify.ACME.Anvil
{
    public class AcmeRequestExceptionTests
    {
        [Fact]
        public void CanCreateException()
        {
            var ex = new AcmeRequestException();
        }

        [Fact]
        public void CanCreateExceptionWithMessage()
        {
            var ex = new AcmeRequestException("certes");
            Assert.Equal("certes", ex.Message);
        }

        [Fact]
        public void CanCreateExceptionWithInnerException()
        {
            var inner = new AcmeException();
            var ex = new AcmeRequestException("certes", inner);
            Assert.Equal("certes", ex.Message);
            Assert.Equal(inner, ex.InnerException);
        }
    }
}
