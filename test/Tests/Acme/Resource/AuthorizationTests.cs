﻿using System;
using Certify.ACME.Anvil.Acme.Resource;
using Xunit;

namespace Certify.ACME.Anvil.Tests.Acme.Resource
{
    public class AuthorizationTests
    {
        [Fact]
        public void CanGetSetProperties()
        {
            var authz = new Authorization();
            authz.VerifyGetterSetter(a => a.Status, AuthorizationStatus.Deactivated);
            authz.VerifyGetterSetter(a => a.Challenges, new[] { new Challenge() });
            authz.VerifyGetterSetter(a => a.Expires, DateTimeOffset.Now);
            authz.VerifyGetterSetter(a => a.Identifier, new Identifier());
            authz.VerifyGetterSetter(a => a.Wildcard, true);
            authz.VerifyGetterSetter(a => a.Scope, new Uri("http://certes.is.working"));
        }
    }
}
