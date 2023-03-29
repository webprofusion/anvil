using Certify.ACME.Anvil.Tests;
using Xunit;

namespace Certify.ACME.Anvil.Acme.Resource
{
    public class CertificateRevocationTests
    {
        [Fact]
        public void CanGetSetProperties()
        {
            var entity = new CertificateRevocation();
            entity.VerifyGetterSetter(e => e.Certificate, "cert");
            entity.VerifyGetterSetter(e => e.Reason, RevocationReason.KeyCompromise);
        }
    }
}
