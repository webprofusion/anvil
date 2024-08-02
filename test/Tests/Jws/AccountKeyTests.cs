using System;
using Newtonsoft.Json;
using System.ComponentModel;
using System.Globalization;
using System.Threading;
using Xunit;
using Certify.ACME.Anvil.Json;

namespace Certify.ACME.Anvil.Jws
{
    public class AccountKeyTests
    {
        [Fact]
        public void CanGetSetProperties()
        {
            var key = new AccountKey();
#pragma warning disable 0612
            Assert.Equal(key.Jwk, key.JsonWebKey);
#pragma warning restore 0612
        }

        [Fact]
        public void CreateWithNull()
        {
            Assert.Throws<ArgumentNullException>(() => new AccountKey(null));
        }

        [Fact, Description("Json Web Key Serialization Order Tests")]
        public void SerializationOrder()
        {

            var serializationSettings = JsonUtil.CreateSettings();
            var cultures = CultureInfo.GetCultures(CultureTypes.AllCultures);

            var rsaKey = KeyFactory.FromPem(Keys.RS256Key);
            var ecKey = KeyFactory.FromPem(Keys.ES256Key);

            foreach (var culture in cultures)
            {
                System.Console.WriteLine($"Testing serialization order for {culture}");
                CultureInfo.CurrentCulture = culture;
                CultureInfo.CurrentUICulture = culture;
                Thread.CurrentThread.CurrentCulture = culture;
                CultureInfo.DefaultThreadCurrentCulture = culture;
                CultureInfo.DefaultThreadCurrentUICulture = culture;

                var jwkRSA = (RsaJsonWebKey)rsaKey.JsonWebKey;

                var json = JsonConvert.SerializeObject(jwkRSA, Formatting.None);

                var expectedJson = """{"e":"AQAB","kty":"RSA","n":"maeT6EsXTVHAdwuq3IlAl9uljXE5CnkRpr6uSw_Fk9nQshfZqKFdeZHkSBvIaLirE2ZidMEYy-rpS1O2j-viTG5U6bUSWo8aoeKoXwYfwbXNboEA-P4HgGCjD22XaXAkBHdhgyZ0UBX2z-jCx1smd7nucsi4h4RhC_2cEB1x_mE6XS5VlpvG91Hbcgml4cl0NZrWPtJ4DhFdPNUtQ8q3AYXkOr_OSFZgRKjesRaqfnSdJNABqlO_jEzAx0fgJfPZe1WlRWOfGRVBVopZ4_N5HpR_9lsNDzCZyidFsHwzvpkP6R6HbS8CMrNWgtkTbnz27EVqIhkYdiPVIN2Xkwj0BQ"}"""; ;

                Assert.Equal(expectedJson, json);

                var jwkEC = (EcJsonWebKey)ecKey.JsonWebKey;

                json = JsonConvert.SerializeObject(jwkEC, Formatting.None);

                expectedJson = """{"crv":"P-256","kty":"EC","x":"dHVy6M_8l7UibLdFPlhnbdNv-LROnx6_FcdyFArBd_s","y":"2xBzsnlAASQN0jQYuxdWybSzEQtsxoT-z7XGIDp0k_c"}"""; ;

                Assert.Equal(expectedJson, json);
            }
        }
    }
}
