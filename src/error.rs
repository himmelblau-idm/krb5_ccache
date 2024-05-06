#[derive(Debug)]
pub enum CCacheError {
    /// Crypto failure
    CryptoFail(String),
    /// Error encountered during formating
    FormatError(String),
    /// Failed to parse something
    InvalidParse(String),
    /// Datetime failure
    DateTime(String),
    /// Reading/Writing from/to a file Failed
    FileOperationFail(String),
    /// This functionality is not yet implemented
    NotImplemented,
}
