using System.Globalization;
using Certify.ACME.Anvil.Properties;
using Xunit;

namespace Certify.ACME.Anvil.Properties
{
    public class StringsTests
    {
        [Fact]
        public void CanCreateInstance()
        {
            var res = new Strings();
        }

#if !NETCOREAPP1_0
        [Fact]
        public void CanGetSetCulture()
        {
            Strings.Culture = CultureInfo.GetCultureInfo("fr-CA");
            Assert.Equal(CultureInfo.GetCultureInfo("fr-CA"), Strings.Culture);
        }
#endif
    }
}
