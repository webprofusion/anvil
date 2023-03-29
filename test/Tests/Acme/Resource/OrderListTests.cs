using System;
using Certify.ACME.Anvil.Tests;
using Xunit;

namespace Certify.ACME.Anvil.Acme.Resource
{
    public class OrderListTests
    {
        [Fact]
        public void CanGetSetProperties()
        {
            var entity = new OrderList();
            entity.VerifyGetterSetter(a => a.Orders, new[] { new Uri("http://certes.is.working") });
        }
    }
}
