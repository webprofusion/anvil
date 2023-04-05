using Newtonsoft.Json;

namespace Certify.ACME.Anvil.Acme.Resource
{
    /// <summary>
    /// Authority Token https://datatracker.ietf.org/doc/html/draft-ietf-acme-authority-token-tnauthlist-13#name-tnauthlist-authority-token
    /// Based on JWT https://www.rfc-editor.org/info/rfc7519
    /// </summary>
    public class AuthorityToken
    {
        /// <summary>
        /// Issuer
        /// </summary>
        [JsonProperty("iss")]
        public string Iss { get; set; }

        /// <summary>
        /// Expiration
        /// </summary>
        [JsonProperty("exp")]
        public int? Exp { get; set; }

        /// <summary>
        /// JWT ID Claim
        /// </summary>
        [JsonProperty("jti")]
        public string Jti { get; set; }

        /// <summary>
        /// Authority Token Challenge claim https://www.ietf.org/archive/id/draft-ietf-acme-authority-token-09.txt
        /// </summary>
        [JsonProperty("atc")]
        public AtcClaim Atc { get; set; }
    }

    /// <summary>
    /// Authority Token Challenge claim
    /// </summary>
    public class AtcClaim
    {
        /// <summary>
        /// Token type e.g. TNAUthList
        /// </summary>
        [JsonProperty(propertyName: "tktype")]
        public string TkType { get; set; }

        /// <summary>
        /// a "tkvalue" key with a string value equal to the base64url encoding. E.g. of the TN Authorization List certificate extension ASN.1 object using DER encoding rules.
        /// "tkvalue" is a required key and MUST be included.
        /// </summary>
        [JsonProperty(propertyName: "tkvalue")]
        public string TkValue { get; set; }

        /// <summary>
        /// a "ca" key with a boolean value set to either true when the requested certificate 
        /// is allowed to be a CA cert for delegation uses or false 
        /// when the requested certificate is not intended to be a CA cert, only an end-entity certificate.
        /// "ca" is an optional key, if not included the "ca" value is considered false by default.
        /// </summary>
        [JsonProperty(propertyName: "ca")]
        public bool? ca { get; set; }

        /// <summary>
        /// a "fingerprint" key is constructed as defined in [RFC8555] Section 8.1 
        /// </summary>
        [JsonProperty(propertyName: "fingerprint")]
        public string Fingerprint { get; set; }
    }
}
