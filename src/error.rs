#[derive(Debug)]
pub enum CCacheError {
    /// Crypto failure
    CryptoFail(String),
    /// Error encountered during formating
    FormatError(String),
    /// This functionality is not yet implemented
    NotImplemented,
}
