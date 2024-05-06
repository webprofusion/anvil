using System;
using System.IO;
using Xunit;

namespace Certify.ACME.Anvil.Acme
{
    public class CertificateChainTests
    {
        [Fact]
        public void CanGenerateFullChainPem()
        {
            var pem =
                string.Join(Environment.NewLine,
                File.ReadAllText("./Data/leaf-cert.pem").Trim(),
                File.ReadAllText("./Data/test-ca2.pem").Trim(),
                File.ReadAllText("./Data/test-root.pem").Trim());

            var chain = new CertificateChain(pem);
            var result = chain.ToPem();
            Assert.Equal(pem.Replace("\r", "").Trim(), result.Replace("\r", "").Trim());
        }

        [Fact]
        public void CanGenerateFullChainPemWithKey()
        {
            var key = KeyFactory.NewKey(KeyAlgorithm.ES256);

            var pem =
                string.Join(Environment.NewLine,
                File.ReadAllText("./Data/cert.pem").Trim());

            var expectedPem =
                key.ToPem().Trim() +
                Environment.NewLine +
                pem;

            var chain = new CertificateChain(pem);
            
            var result = chain.ToPem(key);
            Assert.Equal(expectedPem.ReplaceLineEndings().Trim(), result.ReplaceLineEndings().Trim(), ignoreLineEndingDifferences:true, ignoreWhiteSpaceDifferences:true);
        }

        [Fact]
        public void AllowMissingIssuer()
        {
            var pem =
                string.Join(Environment.NewLine,
                File.ReadAllText("./Data/leaf-cert.pem").Trim(),
                File.ReadAllText("./Data/test-root.pem").Trim());

            var chain = new CertificateChain(pem);
            Assert.NotEmpty(chain.ToPem());

        }
    }
}
