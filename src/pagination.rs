//! Pagination utilities for API responses.

use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

pub const DEFAULT_PER_PAGE: i64 = 20;
pub const MAX_PER_PAGE: i64 = 100;
pub const MIN_PER_PAGE: i64 = 1;

#[derive(Debug, Clone, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PaginationParams {
    /// Page number (1-indexed). Defaults to 1.
    #[param(minimum = 1, default = 1)]
    #[serde(default = "default_page")]
    pub page: i64,

    /// Number of items per page. Defaults to 20, max 100.
    #[param(minimum = 1, maximum = 100, default = 20)]
    #[serde(default = "default_per_page")]
    pub per_page: i64,
}

fn default_page() -> i64 {
    1
}

fn default_per_page() -> i64 {
    DEFAULT_PER_PAGE
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: DEFAULT_PER_PAGE,
        }
    }
}

impl PaginationParams {
    pub fn new(page: i64, per_page: i64) -> Self {
        Self { page, per_page }
    }

    pub fn page(&self) -> i64 {
        self.page.max(1)
    }

    pub fn per_page(&self) -> i64 {
        self.per_page.clamp(MIN_PER_PAGE, MAX_PER_PAGE)
    }

    pub fn limit(&self) -> i64 {
        self.per_page()
    }

    pub fn offset(&self) -> i64 {
        (self.page() - 1) * self.per_page()
    }

    pub fn limit_offset(&self) -> (i64, i64) {
        (self.limit(), self.offset())
    }

    pub fn into_metadata(self, total_count: i64) -> PaginationMeta {
        PaginationMeta::new(self.page(), self.per_page(), total_count)
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginationMeta {
    pub page: i64,
    pub per_page: i64,
    pub total_count: i64,
    pub total_pages: i64,
    pub has_next: bool,
    pub has_prev: bool,
}

impl PaginationMeta {
    pub fn new(page: i64, per_page: i64, total_count: i64) -> Self {
        let total_pages = if total_count == 0 {
            1
        } else {
            (total_count + per_page - 1) / per_page
        };

        Self {
            page,
            per_page,
            total_count,
            total_pages,
            has_next: page < total_pages,
            has_prev: page > 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct PaginatedResponse<T: Serialize> {
    pub data: Vec<T>,
    pub pagination: PaginationMeta,
}

impl<T: Serialize> PaginatedResponse<T> {
    pub fn new(data: Vec<T>, page: i64, per_page: i64, total_count: i64) -> Self {
        Self {
            data,
            pagination: PaginationMeta::new(page, per_page, total_count),
        }
    }

    pub fn from_params(data: Vec<T>, params: &PaginationParams, total_count: i64) -> Self {
        Self::new(data, params.page(), params.per_page(), total_count)
    }

    pub fn empty(params: &PaginationParams) -> Self {
        Self::new(Vec::new(), params.page(), params.per_page(), 0)
    }
}

pub trait IntoPaginated<T: Serialize> {
    fn into_paginated(self, params: &PaginationParams, total_count: i64) -> PaginatedResponse<T>;
}

impl<T: Serialize> IntoPaginated<T> for Vec<T> {
    fn into_paginated(self, params: &PaginationParams, total_count: i64) -> PaginatedResponse<T> {
        PaginatedResponse::from_params(self, params, total_count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_params_defaults() {
        let params = PaginationParams::default();
        assert_eq!(params.page(), 1);
        assert_eq!(params.per_page(), DEFAULT_PER_PAGE);
    }

    #[test]
    fn test_pagination_params_validation() {
        let params = PaginationParams::new(0, 20);
        assert_eq!(params.page(), 1);

        let params = PaginationParams::new(-5, 20);
        assert_eq!(params.page(), 1);

        let params = PaginationParams::new(1, 500);
        assert_eq!(params.per_page(), MAX_PER_PAGE);

        let params = PaginationParams::new(1, 0);
        assert_eq!(params.per_page(), MIN_PER_PAGE);
    }

    #[test]
    fn test_limit_offset() {
        let params = PaginationParams::new(1, 20);
        assert_eq!(params.limit(), 20);
        assert_eq!(params.offset(), 0);

        let params = PaginationParams::new(2, 20);
        assert_eq!(params.limit(), 20);
        assert_eq!(params.offset(), 20);

        let params = PaginationParams::new(3, 10);
        assert_eq!(params.limit(), 10);
        assert_eq!(params.offset(), 20);
    }

    #[test]
    fn test_pagination_meta() {
        let meta = PaginationMeta::new(1, 20, 100);
        assert_eq!(meta.total_pages, 5);
        assert!(meta.has_next);
        assert!(!meta.has_prev);

        let meta = PaginationMeta::new(3, 20, 100);
        assert!(meta.has_next);
        assert!(meta.has_prev);

        let meta = PaginationMeta::new(5, 20, 100);
        assert!(!meta.has_next);
        assert!(meta.has_prev);

        let meta = PaginationMeta::new(1, 20, 0);
        assert_eq!(meta.total_pages, 1);
        assert!(!meta.has_next);
        assert!(!meta.has_prev);

        let meta = PaginationMeta::new(1, 20, 95);
        assert_eq!(meta.total_pages, 5);
    }

    #[test]
    fn test_paginated_response() {
        let items = vec!["a", "b", "c"];
        let params = PaginationParams::new(1, 10);
        let response = items.into_paginated(&params, 25);

        assert_eq!(response.data.len(), 3);
        assert_eq!(response.pagination.total_count, 25);
        assert_eq!(response.pagination.total_pages, 3);
        assert!(response.pagination.has_next);
        assert!(!response.pagination.has_prev);
    }
}
