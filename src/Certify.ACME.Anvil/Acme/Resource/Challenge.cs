using System;
using System.Collections.Generic;
using Newtonsoft.Json;

namespace Certify.ACME.Anvil.Acme.Resource
{
    /// <summary>
    /// Represents a challenge for <see cref="Identifier"/>.
    /// </summary>
    public class Challenge
    {
        /// <summary>
        /// Gets or sets the type.
        /// </summary>
        /// <value>
        /// The type.
        /// </value>
        [JsonProperty("type")]
        public string Type { get; set; }

        /// <summary>
        /// Gets or sets the URL.
        /// </summary>
        /// <value>
        /// The URL.
        /// </value>
        [JsonProperty("url")]
        public Uri Url { get; set; }

        /// <summary>
        /// Gets or sets the status.
        /// </summary>
        /// <value>
        /// The status.
        /// </value>
        [JsonProperty("status")]
        public ChallengeStatus? Status { get; set; }

        /// <summary>
        /// Gets or sets the validation time.
        /// </summary>
        /// <value>
        /// The validation time.
        /// </value>
        [JsonProperty("validated")]
        public DateTimeOffset? Validated { get; set; }

        /// <summary>
        /// Gets or sets the error.
        /// Only if the status is invalid
        /// </summary>
        /// <value>
        /// The errors.
        /// </value>
        [JsonProperty("error")]
        public AcmeError Error { get; set; }

        /// <summary>
        /// Gets or sets the errors.
        /// </summary>
        /// <value>
        /// The errors.
        /// </value>
        [JsonProperty("errors")]
        [Obsolete("Use Challenge.Error instead.")]
        public IList<object> Errors { get; set; }

        /// <summary>
        /// Gets or sets the token.
        /// </summary>
        /// <value>
        /// The token.
        /// </value>
        [JsonProperty("token")]
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the key authorization.
        /// </summary>
        /// <value>
        /// The key authorization.
        /// </value>
        [JsonProperty("keyAuthorization")]
        [Obsolete("Removed from ACME server.")]
        public string KeyAuthorization { get; set; }

        /// <summary>
        /// Gets or sets the tkauth-type (for acme-authority-token) for applicable ACME challenges.
        /// </summary>
        /// <value>
        /// The tkauth-type, if present, e.g. "atc"
        /// </value>
        [JsonProperty("tkauth-type")]

        public string TkAuthType { get; set; }

        /// <summary>
        /// Gets or sets the token authority for acme-authority-token
        /// </summary>
        /// <value>
        /// The token authority, if applicable
        /// </value>
        [JsonProperty("token-authority")]

        public string TokenAuthority { get; set; }

    }
}
