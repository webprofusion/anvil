using System;
using Certify.ACME.Anvil.Acme;
using Certify.ACME.Anvil.Json;
using Newtonsoft.Json;

namespace Certify.ACME.Anvil
{
    /// <summary>
    /// The exception that is thrown when an error occurs while processing ACME operations.
    /// </summary>
    /// <seealso cref="AcmeException" />
    [Serializable]
    public class AcmeRequestException : AcmeException
    {
        /// <summary>
        /// The json serializer settings for converting additional information.
        /// </summary>
        private static readonly JsonSerializerSettings jsonSerializerSettings = JsonUtil.CreateSettings();

        /// <summary>
        /// Gets the error occurred while processing ACME operations.
        /// </summary>
        /// <value>
        /// The error occurred while processing ACME operations.
        /// </value>
        public AcmeError Error { get; private set; }

        /// <summary>
        /// Gets the delay in seconds requested by the server via the Retry-After header, or zero if not supplied.
        /// </summary>
        /// <value>
        /// The retry delay in seconds.
        /// </value>
        public int RetryAfter { get; private set; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeRequestException"/> class.
        /// </summary>
        public AcmeRequestException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeRequestException"/> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public AcmeRequestException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeException" /> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="error">The error occurred while processing ACME operations.</param>
        public AcmeRequestException(string message, AcmeError error)
            : base(message)
        {
            Error = error;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeException" /> class.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="error">The error occurred while processing ACME operations.</param>
        /// <param name="retryAfter">The retry delay in seconds requested by the server, if any.</param>
        public AcmeRequestException(string message, AcmeError error, int retryAfter)
            : base(message)
        {
            Error = error;
            RetryAfter = retryAfter;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AcmeRequestException"/> class.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception.
        /// </param>
        /// <param name="innerException">
        /// The exception that is the cause of the current exception, 
        /// or a null reference (Nothing in Visual Basic) if no inner
        /// exception is specified.
        /// </param>
        public AcmeRequestException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Gets a message that describes the current exception.
        /// </summary>
        public override string Message
        {
            get
            {
                if (Error != null)
                {
                    return $"{base.Message}\n{Error?.Type}: {Error?.Detail}";
                }

                return base.Message;
            }
        }
    }
}
