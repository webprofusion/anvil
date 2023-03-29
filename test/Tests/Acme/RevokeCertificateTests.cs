using Certify.ACME.Anvil.Acme;
using Xunit;

namespace Certify.ACME.Anvil.Tests
{
    public class RevokeCertificateTests
    {

        [Fact]
        public void CanGetSetProperties()
        {
            var authz = new RevokeCertificateEntity();
            authz.VerifyGetterSetter(a => a.Certificate, "pem");
        }
    }
}
