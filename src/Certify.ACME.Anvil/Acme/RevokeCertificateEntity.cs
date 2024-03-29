﻿namespace Certify.ACME.Anvil.Acme
{
    /// <summary>
    /// Represents the ACME revoke certificate entity.
    /// </summary>
    /// <seealso cref="Certify.ACME.Anvil.Acme.EntityBase" />
    public class RevokeCertificateEntity : EntityBase
    {
        /// <summary>
        /// Gets or sets the encoded certificate.
        /// </summary>
        /// <value>
        /// The encoded certificate.
        /// </value>
        public string Certificate { get; set; }
    }
}
