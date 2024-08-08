using System;
using Newtonsoft.Json;

namespace Certify.ACME.Anvil.Acme
{
    /// <summary>
    /// Represents the ACME RenewalInfo resource (draft) https://www.ietf.org/id/draft-ietf-acme-ari-04.html
    ///    
    /// {
    ///  "suggestedWindow": {
    ///   "start": "2021-01-03T00:00:00Z",
    ///   "end": "2021-01-07T00:00:00Z"
    ///   },
    ///  "explanationURL": "https://example.com/docs/example-mass-reissuance-event"
    /// }
    /// </summary>
    public class AcmeRenewalInfo
    {
        /// <summary>
        /// Gets or sets the suggestedWindow.
        /// </summary>
        /// <value>
        /// The expires.
        /// </value>
        [JsonProperty("suggestedWindow")]
        public AcmeRenewalWindow SuggestedWindow { get; set; }


        /// <summary>
        /// The URL to an explanation of the suggested renewal window
        /// </summary>
        [JsonProperty("explanationURL")]
        public Uri ExplanationURL { get; set; }

    }

    /// <summary>
    /// ACME RenewalWindow
    /// </summary>
    public class AcmeRenewalWindow
    {
        /// <summary>
        /// Start of renewal window
        /// </summary>
        [JsonProperty("start")]
        public DateTimeOffset? Start { get; set; }

        /// <summary>
        /// End of renewal window
        /// </summary>
        [JsonProperty("end")]
        public DateTimeOffset? End { get; set; }
    }
}
