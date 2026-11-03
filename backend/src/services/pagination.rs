//! Page-based list parameters and the list response shape from `specs/api.md` (Lists).

use serde::Serialize;

use crate::error::AppError;

pub const DEFAULT_PAGE_SIZE: i64 = 50;
pub const MAX_PAGE_SIZE: i64 = 200;

/// Validated `page`, `page_size`, `sort`, and `order` query values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pagination {
    pub page: i64,
    pub page_size: i64,
    pub sort: String,
    pub ascending: bool,
}

impl Pagination {
    /// Validates raw query values. `allowed_sorts` lists the sort keys the route
    /// accepts, and the first one is the default. Any violation is a `400`.
    pub fn parse(
        page: Option<i64>,
        page_size: Option<i64>,
        sort: Option<&str>,
        order: Option<&str>,
        allowed_sorts: &[&str],
    ) -> Result<Self, AppError> {
        let page = page.unwrap_or(1);
        if page < 1 {
            return Err(AppError::InvalidRequest(
                "page must be 1 or more.".to_owned(),
            ));
        }
        let page_size = page_size.unwrap_or(DEFAULT_PAGE_SIZE);
        if !(1..=MAX_PAGE_SIZE).contains(&page_size) {
            return Err(AppError::InvalidRequest(format!(
                "page_size must be between 1 and {MAX_PAGE_SIZE}."
            )));
        }
        let default_sort = allowed_sorts.first().ok_or(AppError::InternalError)?;
        let sort = match sort {
            None => (*default_sort).to_owned(),
            Some(value) if allowed_sorts.contains(&value) => value.to_owned(),
            Some(_) => {
                return Err(AppError::InvalidRequest(
                    "sort is not allowed for this list.".to_owned(),
                ));
            }
        };
        let ascending = match order {
            None | Some("desc") => false,
            Some("asc") => true,
            Some(_) => {
                return Err(AppError::InvalidRequest(
                    "order must be asc or desc.".to_owned(),
                ));
            }
        };
        Ok(Self {
            page,
            page_size,
            sort,
            ascending,
        })
    }

    /// Row offset for the page. Saturates instead of overflowing on huge pages.
    pub fn offset(&self) -> i64 {
        (self.page - 1).saturating_mul(self.page_size)
    }
}

/// Response shape for every list route: `{"items", "page", "page_size", "total"}`.
#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: i64,
    pub page_size: i64,
    pub total: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_applied() {
        let p = Pagination::parse(None, None, None, None, &["created_at"]).expect("valid");
        assert_eq!(
            (p.page, p.page_size, p.sort.as_str(), p.ascending),
            (1, 50, "created_at", false)
        );
        assert_eq!(p.offset(), 0);
    }

    #[test]
    fn oversized_page_size_is_rejected() {
        let r = Pagination::parse(None, Some(201), None, None, &["created_at"]);
        assert!(matches!(r, Err(AppError::InvalidRequest(_))));
    }

    #[test]
    fn unknown_sort_is_rejected() {
        let r = Pagination::parse(None, None, Some("target"), None, &["created_at"]);
        assert!(matches!(r, Err(AppError::InvalidRequest(_))));
    }

    #[test]
    fn zero_page_and_bad_order_are_rejected() {
        assert!(Pagination::parse(Some(0), None, None, None, &["created_at"]).is_err());
        assert!(Pagination::parse(None, None, None, Some("up"), &["created_at"]).is_err());
    }
}
