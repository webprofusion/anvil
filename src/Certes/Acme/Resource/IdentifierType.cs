using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace Certes.Acme.Resource
{
    /// <summary>
    /// Represents type of <see cref="Identifier"/>.
    /// </summary>
    [JsonConverter(typeof(StringEnumConverter))]
    public enum IdentifierType
    {
        /// <summary>
        /// The DNS type.
        /// </summary>
        [EnumMember(Value = "dns")]
        Dns,

        /// <summary>
        /// The IP type.
        /// </summary>
        [EnumMember(Value = "ip")]
        Ip,

        /// <summary>
        /// The TNAuthList type (Telephone Number Authority List Authority Token) https://datatracker.ietf.org/doc/html/draft-ietf-acme-authority-token-tnauthlist-13 
        /// </summary>
        [EnumMember(Value = "TNAuthList")]
        TNAuthList
    }
}
