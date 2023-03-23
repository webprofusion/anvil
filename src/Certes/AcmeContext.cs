using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Jws;
using Identifier = Certes.Acme.Resource.Identifier;
using IdentifierType = Certes.Acme.Resource.IdentifierType;

namespace Certes
{
    /// <summary>
    /// Represents the context for ACME operations.
    /// </summary>
    /// <seealso cref="Certes.IAcmeContext" />
    public class AcmeContext : IAcmeContext
    {
        private const KeyAlgorithm defaultKeyType = KeyAlgorithm.ES256;
        private Directory directory;
        private IAccountContext accountContext = null;

        /// <summary>
        /// Gets the number of retries on a badNonce error.
        /// </summary>
        /// <value>
        /// The number of retries.
        /// </value>
        public int BadNonceRetryCount { get; }

        /// <summary>
        /// Gets the ACME HTTP client.
        /// </summary>
        /// <value>
        /// The ACME HTTP client.
        /// </value>
        public IAcmeHttpClient HttpClient { get; }

        /// <summary>
        /// Gets the directory URI.
        /// </summary>
        /// <value>
        /// The directory URI.
        /// </value>
        public Uri DirectoryUri { get; }

        /// <summary>
        /// Gets the account key.
        /// </summary>
        /// <value>
        /// The account key.
        /// </value>
        public IKey AccountKey { get; private set; }

        /// <summary>
        /// Optional account uri, can be derived via ACME otherwise
        /// </summary>
        private Uri accountUri { get; set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeContext" /> class.
        /// </summary>
        /// <param name="directoryUri">The directory URI.</param>
        /// <param name="accountKey">The account key.</param>
        /// <param name="http">The HTTP client.</param>
        /// <param name="badNonceRetryCount">The number of retries on a bad nonce.</param>
        /// <param name="accountUri">Optional account URI.</param>
        /// <exception cref="ArgumentNullException">
        /// If <paramref name="directoryUri"/> is <c>null</c>.
        /// </exception>
        public AcmeContext(Uri directoryUri, IKey accountKey = null, IAcmeHttpClient http = null, int badNonceRetryCount = 1, Uri accountUri = null)
        {
            DirectoryUri = directoryUri ?? throw new ArgumentNullException(nameof(directoryUri));
            AccountKey = accountKey ?? KeyFactory.NewKey(defaultKeyType);
            HttpClient = http ?? new AcmeHttpClient(directoryUri);
            BadNonceRetryCount = badNonceRetryCount;
            this.accountUri = accountUri;
        }

        /// <summary>
        /// Gets the ACME account context.
        /// </summary>
        /// <returns>The ACME account context.</returns>
        public async Task<IAccountContext> Account()
        {
            if (accountContext != null)
            {
                return accountContext;
            }

            var resp = await AccountContext.NewAccount(this, new Account.Payload { OnlyReturnExisting = true }, true);
            return accountContext = new AccountContext(this, resp.Location);
        }

        /// <summary>
        /// Get AccountUri if known, or fetch via ACME
        /// </summary>
        /// <returns></returns>
        public async Task<Uri> GetAccountUri()
        {
            if (accountUri != null)
            {
                return accountUri;
            }
            else
            {
                accountUri = await Account().Location();
                return accountUri;
            }
        }

        /// <summary>
        /// Changes the account key.
        /// </summary>
        /// <param name="key">The new account key.</param>
        /// <returns>The account resource.</returns>
        public async Task<Account> ChangeKey(IKey key)
        {
            var endpoint = await this.GetResourceUri(d => d.KeyChange);
            var location = await GetAccountUri();

            var newKey = key ?? KeyFactory.NewKey(defaultKeyType);
            var keyChange = new
            {
                account = location,
                oldKey = AccountKey.JsonWebKey,
            };

            var jws = new JwsSigner(newKey);
            var body = jws.Sign(keyChange, url: endpoint);

            var resp = await HttpClient.Post<Account>(this, endpoint, body, true);

            AccountKey = newKey;
            return resp.Resource;
        }

        /// <summary>
        /// Creates the account.
        /// </summary>
        /// <returns>
        /// The account created.
        /// </returns>
        public async Task<IAccountContext> NewAccount(IList<string> contact, bool termsOfServiceAgreed, string eabKeyId = null, string eabKey = null, string eabKeyAlg = null)
        {
            var body = new Account
            {
                Contact = contact,
                TermsOfServiceAgreed = termsOfServiceAgreed
            };

            var resp = await AccountContext.NewAccount(this, body, true, eabKeyId, eabKey, eabKeyAlg);
            return accountContext = new AccountContext(this, resp.Location);
        }

        /// <summary>
        /// Gets the ACME directory.
        /// </summary>
        /// <returns>
        /// The ACME directory.
        /// </returns>
        public async Task<Directory> GetDirectory(bool throwOnError = false)
        {
            if (directory == null)
            {
                try
                {
                    var resp = await HttpClient.Get<Directory>(DirectoryUri);

                    if (resp.Error != null && throwOnError)
                    {
                        throw new AcmeException(resp.Error.Detail);
                    }

                    directory = resp.Resource;
                }
                catch (Exception exp)
                {
                    if (throwOnError)
                    {
                        // testing the directory URL can also be used to diagnose connectivity to service downtime, 
                        // so some consumers will want the exception instead of a null directory
                        if (exp is AcmeException)
                        {
                            throw;
                        }
                        else
                        {
                            throw new AcmeException("The ACME service (directory) is unavailable.", exp);
                        }
                    }
                }
            }

            return directory;
        }

        /// <summary>
        /// Revokes the certificate.
        /// </summary>
        /// <param name="certificate">The certificate in DER format.</param>
        /// <param name="reason">The reason for revocation.</param>
        /// <param name="certificatePrivateKey">The certificate's private key.</param>
        /// <returns>
        /// The awaitable.
        /// </returns>
        public async Task RevokeCertificate(byte[] certificate, RevocationReason reason, IKey certificatePrivateKey)
        {
            var endpoint = await this.GetResourceUri(d => d.RevokeCert);

            var body = new CertificateRevocation
            {
                Certificate = JwsConvert.ToBase64String(certificate),
                Reason = reason
            };

            if (certificatePrivateKey != null)
            {
                var jws = new JwsSigner(certificatePrivateKey);
                await HttpClient.Post<string>(jws, endpoint, body, true);
            }
            else
            {
                await HttpClient.Post<string>(this, endpoint, body, true);

            }
        }

        /// <summary>
        /// Creates a new the order.
        /// </summary>
        /// <param name="identifiers">The (dns) identifiers.</param>
        /// <param name="notBefore">Th value of not before field for the certificate.</param>
        /// <param name="notAfter">The value of not after field for the certificate.</param>
        /// <returns>
        /// The order context created.
        /// </returns>
        public async Task<IOrderContext> NewOrder(IList<string> identifiers, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            var endpoint = await this.GetResourceUri(d => d.NewOrder);

            var body = new Order
            {
                Identifiers = identifiers
                    .Select(id => new Identifier
                    {
                        Type = IdentifierType.Dns,
                        Value = id
                    })
                    .ToArray(),
                NotBefore = notBefore,
                NotAfter = notAfter,
            };

            var order = await HttpClient.Post<Order>(this, endpoint, body, true);
            return new OrderContext(this, order.Location);
        }

        /// <summary>
        /// Creates a new the order.
        /// </summary>
        /// <param name="identifiers">The identifiers.</param>
        /// <param name="notBefore">Th value of not before field for the certificate.</param>
        /// <param name="notAfter">The value of not after field for the certificate.</param>
        /// <returns>
        /// The order context created.
        /// </returns>
        public async Task<IOrderContext> NewOrder(IList<Identifier> identifiers, DateTimeOffset? notBefore = null, DateTimeOffset? notAfter = null)
        {
            var endpoint = await this.GetResourceUri(d => d.NewOrder);

            var body = new Order
            {
                Identifiers = identifiers.ToArray(),
                NotBefore = notBefore,
                NotAfter = notAfter,
            };

            var order = await HttpClient.Post<Order>(this, endpoint, body, true);
            return new OrderContext(this, order.Location);
        }

        /// <summary>
        /// Signs the data with account key.
        /// </summary>
        /// <param name="entity">The data to sign.</param>
        /// <param name="uri">The URI for the request.</param>
        /// <returns>The JWS payload.</returns>
        public async Task<JwsPayload> Sign(object entity, Uri uri)
        {
            var nonce = await HttpClient.ConsumeNonce();
            var location = await GetAccountUri();
            var jws = new JwsSigner(AccountKey);
            return jws.Sign(entity, location, uri, nonce);
        }

        /// <summary>
        /// Gets the order by specified location.
        /// </summary>
        /// <param name="location">The order location.</param>
        /// <returns>
        /// The order context.
        /// </returns>
        public IOrderContext Order(Uri location)
            => new OrderContext(this, location);

        /// <summary>
        /// Gets the authorization by specified location.
        /// </summary>
        /// <param name="location">The authorization location.</param>
        /// <returns>
        /// The authorization context.
        /// </returns>
        public IAuthorizationContext Authorization(Uri location)
            => new AuthorizationContext(this, location);

        /// <summary>
        /// Get renewal info for given certificate id
        /// </summary>
        /// <param name="certificateId">The CertID (see OCSP Cert ID, this is a base64url encoded hash of cert public key and serial)</param>
        /// <returns></returns>
        public async Task<AcmeRenewalInfo> GetRenewalInfo(string certificateId)
        {
            var uri = await this.GetResourceUri(d => d.RenewalInfo);

            var resourceUri = new Uri($"{uri.ToString().TrimEnd('/')}/{certificateId}");

            var resp = await HttpClient.Get<AcmeRenewalInfo>(resourceUri);

            return resp.Resource;

        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="certificateId"></param>
        /// <param name="replaced"></param>
        /// <returns></returns>
        public async Task<bool> UpdateRenewalInfo(string certificateId, bool replaced)
        {
            var endpoint = await this.GetResourceUri(d => d.RenewalInfo);

            var resp = await HttpClient.Post<RenewalUpdate>(endpoint, new RenewalUpdate { CertId = certificateId, Replaced = replaced });

            if (resp.Error != null)
            {
                return false;
            }
            else
            {
                return true;
            }
        }

        /// <summary>
        /// Set cached accountURI
        /// </summary>
        /// <param name="accountUri"></param>
        public void SetAccountUri(Uri accountUri)
        {
            this.accountUri = accountUri;
        }
    }
}
