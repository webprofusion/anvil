﻿using System;
using Xunit;

namespace Certify.ACME.Anvil.Acme.Resource
{
    public class DirectoryTests
    {
        [Fact]
        public void CanGetSetProperties()
        {
            var data = new
            {
                NewNonce = new Uri("http://NewNonce.is.working"),
                RevokeCert = new Uri("http://RevokeCert.is.working"),
                KeyChange = new Uri("http://KeyChange.is.working"),
                NewAccount = new Uri("http://NewAccount.is.working"),
                NewOrder = new Uri("http://NewOrder.is.working"),
                RenewalInfo = new Uri("http://RenewalInfo.is.working"),
                Meta = new DirectoryMeta(new Uri("http://certes.is.working"), null, null, null),
            };

            var model = new Directory(
                data.NewNonce,
                data.NewAccount,
                data.NewOrder,
                data.RevokeCert,
                data.KeyChange,
                data.RenewalInfo,
                data.Meta);

            Assert.Equal(data.NewNonce, model.NewNonce);
            Assert.Equal(data.NewAccount, model.NewAccount);
            Assert.Equal(data.NewOrder, model.NewOrder);
            Assert.Equal(data.RevokeCert, model.RevokeCert);
            Assert.Equal(data.KeyChange, model.KeyChange);
            Assert.Equal(data.RenewalInfo, model.RenewalInfo);
            Assert.Equal(data.Meta.Website, model.Meta?.Website);
        }
    }
}
