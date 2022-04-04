namespace Certes.Crypto
{
    /// <summary>
    /// Provider for key algorithms
    /// </summary>
    public interface IKeyAlgorithm
    {
        /// <summary>
        /// Create signer
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        ISigner CreateSigner(IKey keyPair);

        /// <summary>
        /// Generate Key
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        IKey GenerateKey(int? keySize = null);
    }
}
