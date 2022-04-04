namespace Certes.Pkcs
{
    /// <summary>
    /// Supports building Certificate Signing Request (CSR).
    /// </summary>
    public interface ICertificationRequestBuilder
    {
        /// <summary>
        /// Generates the CSR.
        /// </summary>
        /// <returns>The CSR data.</returns>
        byte[] Generate(bool requireOcspMustStaple = false);

        /// <summary>
        /// Exports the key used to generate the CSR.
        /// </summary>
        /// <returns>The key data.</returns>
        KeyInfo Export();
    }
}
