using System;
using System.Net.Http;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;
using Directory = Certify.ACME.Anvil.Acme.Resource.Directory;

namespace Certify.ACME.Anvil.Tests
{
    public static partial class Helper
    {
        public static string TestCI_Domain1 => "anvil-ci-01.webprofusion.com";
        public static string TestDomain1 => "anvil-test-01.webprofusion.com";
        public static string TestDomain2 => "anvil-test-02.webprofusion.com";
        public static string TestDomain3 => "anvil-test-03.webprofusion.com";

        public static readonly Directory MockDirectoryV2 = new Directory(
            new Uri("http://acme.d/newNonce"),
            new Uri("http://acme.d/newAccount"),
            new Uri("http://acme.d/newOrder"),
            new Uri("http://acme.d/revokeCert"),
            new Uri("http://acme.d/keyChange"),
            new Uri("http://acme.d/renewalInfo"),
            new DirectoryMeta(new Uri("http://acme.d/tos"), null, null, false));

        public static IKey GetKeyV2(KeyAlgorithm algo = KeyAlgorithm.ES256)
            => KeyFactory.FromPem(algo.GetTestKey());

        public static IAcmeHttpClient CreateHttp(Uri dirUri, HttpClient http)
            => new AcmeHttpClient(dirUri, http);
    }
}
