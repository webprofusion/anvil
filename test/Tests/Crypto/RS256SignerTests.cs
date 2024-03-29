﻿using System;
using Moq;
using Xunit;

namespace Certify.ACME.Anvil.Crypto
{
    public class RS256SignerTests
    {
        [Fact]
        public void InvalidPrivateKey()
        {
            var provider = new KeyAlgorithmProvider();
            var algo = provider.Get(KeyAlgorithm.ES256);
            var key = algo.GenerateKey();

            Assert.Throws<ArgumentException>(() => new RS256Signer(key));
        }

        [Fact]
        public void InvalidKey()
        {
            var mock = new Mock<IKey>();
            var obj = mock.Object;
            Assert.Throws<ArgumentException>(() => new RS256Signer(obj));
        }
    }
}
