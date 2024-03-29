﻿using System;
using Xunit;

namespace Certify.ACME.Anvil.Pkcs
{
    public class SignatureAlgorithmTests
    {
        [Fact]
        public void ToJwsAlgorithmInvalid()
        {
            Assert.Throws<ArgumentException>(() =>
                ((KeyAlgorithm)1000).ToJwsAlgorithm());
        }

        [Fact]
        public void ToPkcsObjectIdInvalid()
        {
            Assert.Null(
                ((KeyAlgorithm)1000).ToPkcsObjectId());
        }
    }
}
