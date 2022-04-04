using System.IO;
using Xunit;
using Certes.Acme;

#if !NETCOREAPP1_0
using System.Runtime.Serialization.Formatters.Binary;
#endif

namespace Certes
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
