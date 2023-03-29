using System;
using Xunit;

namespace Certify.ACME.Anvil.Crypto
{
    public class AsymmetricCipherSignatureKeyTests
    {
        [Fact]
        public void CtorNull()
        {
            Assert.Throws<ArgumentNullException>(() => new AsymmetricCipherKey(KeyAlgorithm.ES256, null));
        }
    }
}
