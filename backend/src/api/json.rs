//! Request-body parsing shared by the spinoff routes.

use serde::Deserialize;

use crate::error::AppError;

/// Parses a JSON body into `T`. A malformed body becomes `400 invalid_request`. The error text
/// is fixed: it never repeats the body, which can hold a token.
pub fn parse_body<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AppError> {
    serde_json::from_slice(bytes)
        .map_err(|_| AppError::InvalidRequest("The request body is not valid.".to_owned()))
}
