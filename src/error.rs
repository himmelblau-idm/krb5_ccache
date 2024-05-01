#[derive(Debug)]
pub enum CCacheError {
    /// Error encountered during formating
    FormatError(String),
    /// This functionality is not yet implemented
    NotImplemented,
}
