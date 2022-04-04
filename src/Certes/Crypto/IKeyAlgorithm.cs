namespace Certes.Crypto
{
    /// <summary>
    /// Provides signer algorithms
    /// </summary>
    public interface IKeyAlgorithm
    {
        /// <summary>
        /// Create a signer for the given key pair
        /// </summary>
        /// <param name="keyPair"></param>
        /// <returns></returns>
        ISigner CreateSigner(IKey keyPair);
        
        /// <summary>
        /// Generate a key, using given keysize if applicable
        /// </summary>
        /// <param name="keySize"></param>
        /// <returns></returns>
        IKey GenerateKey(int? keySize = null);
    }
}
