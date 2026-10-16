using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Acme.Resource;
using Certify.ACME.Anvil.Jws;

namespace Certify.ACME.Anvil
{
    /// <summary>
    /// Represents the context for ACME operations.
    /// </summary>
    public interface IAcmeContext
    {

        /// <summary>
        /// Gets the number of retries on a badNonce error.
        /// </summary>
        /// <value>
        /// The number of retries.
        /// </value>
        int BadNonceRetryCount { get; }

        /// <summary>
        /// Gets the directory URI.
        /// </summary>
        /// <value>
        /// The directory URI.
        /// </value>
        Uri DirectoryUri { get; }

        /// <summary>
        /// Gets the ACME HTTP client.
        /// </summary>
        /// <value>
        /// The ACME HTTP client.
        /// </value>
        IAcmeHttpClient HttpClient { get; }

        /// <summary>
        /// Gets the account key.
        /// </summary>
        /// <value>
        /// The account key.
        /// </value>
        IKey AccountKey { get; }

        /// <summary>
        /// Gets the ACME account context.
        /// </summary>
        /// <param name="accountUri">Optional URI to initialize account, otherwise an ACME account query is performed</param>
        /// <returns>The ACME account context.</returns>
        Task<IAccountContext> Account(Uri accountUri = null);

        /// <summary>
        /// Get cached Account URI or fetch via ACME
        /// </summary>
        /// <returns></returns>
        Task<Uri> GetAccountUri();

        /// <summary>
        /// Set cached account URI
        /// </summary>
        void SetAccountUri(Uri accountUri);

        /// <summary>
        /// Gets the ACME directory.
        /// </summary>
        /// <param name="throwOnError">If true, throw an AcmeException if we can't fetch the directory or we get an Error response</param>
        /// <returns>
        /// The ACME directory.
        /// </returns>
        Task<Directory> GetDirectory(bool throwOnError = false);

        /// <summary>
        /// Creates an account.
        /// </summary>
        /// <param name="contact">The contact.</param>
        /// <param name="termsOfServiceAgreed">Set to <c>true</c> to accept the terms of service.</param>
        /// <param name="eabKeyId">Optional key identifier, if using external account binding.</param>
        /// <param name="eabKey">Optional EAB key, if using external account binding.</param>
        /// <param name="eabKeyAlg">Optional EAB key algorithm, if using external account binding, defaults to HS256 if not specified</param>
        /// <returns>
        /// The account created.
        /// </returns>
        Task<IAccountContext> NewAccount(IList<string> contact, bool termsOfServiceAgreed = false, string eabKeyId = null, string eabKey = null, string eabKeyAlg = null);

        /// <summary>
        /// Revokes the certificate.
        /// </summary>
        /// <param name="certificate">The certificate in DER format.</param>
        /// <param name="reason">The reason for revocation.</param>
        /// <param name="certificatePrivateKey">The certificate's private key.</param>
        /// <returns>
        /// The awaitable.
        /// </returns>
        Task RevokeCertificate(byte[] certificate, RevocationReason reason = RevocationReason.Unspecified, IKey certificatePrivateKey = null);

        /// <summary>
        /// Changes the account key.
        /// </summary>
        /// <param name="key">The new account key.</param>
        /// <returns>The account resource.</returns>
        Task<Account> ChangeKey(IKey key = null);

        /// <summary>
        /// Creates a new the order.
        /// </summary>
        /// <param name="identifiers">The identifiers.</param>
        /// <param name="notBefore">Th value of not before field for the certificate.</param>
        /// <param name="notAfter">The value of not after field for the certificate.</param>
        /// <param name="ariReplacesCertId">ARI Cert Id of cert being replaced (optional)</param>
        /// <param name="profile">ACME Profile selection for the new cert (optional)</param>
        /// <returns>
        /// The order context created.
        /// </returns>
        Task<IOrderContext> NewOrder(IList<string> identifiers, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null, string ariReplacesCertId = null, string profile = null);

        /// <summary>
        /// Signs the data with account key.
        /// </summary>
        /// <param name="entity">The data to sign.</param>
        /// <param name="uri">The URI for the request.</param>
        /// <returns>The JWS payload.</returns>
        Task<JwsPayload> Sign(object entity, Uri uri);

        /// <summary>
        /// Gets the order by specified location.
        /// </summary>
        /// <param name="location">The order location.</param>
        /// <returns>The order context.</returns>
        IOrderContext Order(Uri location);

        /// <summary>
        /// Gets the authorization by specified location.
        /// </summary>
        /// <param name="location">The authorization location.</param>
        /// <returns>The authorization context.</returns>
        IAuthorizationContext Authorization(Uri location);

        /// <summary>
        /// Get renewal info for given certificate id
        /// </summary>
        /// <param name="certificateId">The CertID (see OCSP Cert ID, this is a base64url encoded hash of cert public key and serial)</param>
        /// <returns></returns>
        Task<AcmeRenewalInfo> GetRenewalInfo(string certificateId);

        /// <summary>
        /// Update ARI renewal info, if provider doesn't support ARI or update fails the exception is catch and no further action is taken
        /// </summary>
        /// <param name="certificateId"></param>
        /// <param name="replaced"></param>
        /// <returns></returns>
        Task UpdateRenewalInfo(string certificateId, bool replaced);
    }
}
