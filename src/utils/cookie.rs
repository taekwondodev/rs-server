use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

use crate::{app::AppError, config::origin::OriginConfig};

const PATH: &str = "/auth";
const HTTP_ONLY: bool = true;
const MAX_AGE: Duration = Duration::days(1);
pub const REFRESH_TOKEN_COOKIE_NAME: &str = "refresh_token";

#[derive(Debug, Clone)]
pub struct CookieService {
    pub secure: bool,
    pub same_site: SameSite,
    pub domain: Option<String>,
    pub path: String,
    pub http_only: bool,
    pub max_age: Duration,
}

impl CookieService {
    pub fn new(origin_config: &OriginConfig) -> Self {
        let is_https = origin_config.frontend_url.scheme() == "https";
        let is_local = origin_config.backend_domain.contains("localhost")
            || origin_config.backend_domain.contains("127.0.0.1");

        Self {
            secure: is_https,
            same_site: Self::determine_same_site(is_https, is_local),
            domain: Self::determine_cookie_domain(origin_config, is_local),
            path: String::from(PATH),
            http_only: HTTP_ONLY,
            max_age: MAX_AGE,
        }
    }

    pub fn create_refresh_token_cookie(&self, token: &str) -> Cookie<'static> {
        self.build_cookie(REFRESH_TOKEN_COOKIE_NAME, token, Some(self.max_age))
    }

    pub fn get_refresh_token_from_jar(
        &self,
        jar: &axum_extra::extract::CookieJar,
    ) -> Result<String, AppError> {
        jar.get(REFRESH_TOKEN_COOKIE_NAME)
            .map(|cookie| cookie.value().to_owned())
            .ok_or_else(|| {
                AppError::Unauthorized(String::from("Refresh token not found in cookies"))
            })
    }

    pub fn clear_refresh_token_cookie(&self) -> Cookie<'static> {
        self.build_cookie(REFRESH_TOKEN_COOKIE_NAME, "", Some(Duration::seconds(-1)))
    }

    fn build_cookie<N, V>(&self, name: N, value: V, max_age: Option<Duration>) -> Cookie<'static>
    where
        N: Into<String>,
        V: Into<String>,
    {
        let mut cookie_builder = Cookie::build((name.into(), value.into()))
            .path(self.path.clone())
            .http_only(self.http_only)
            .secure(self.secure)
            .same_site(self.same_site);

        if let Some(age) = max_age {
            cookie_builder = cookie_builder.max_age(age);
        }

        if let Some(ref domain) = self.domain {
            cookie_builder = cookie_builder.domain(domain.clone());
        }

        cookie_builder.build()
    }

    pub(crate) fn determine_same_site(is_https: bool, is_local: bool) -> SameSite {
        if is_https {
            SameSite::Strict
        } else if is_local {
            SameSite::Lax
        } else {
            SameSite::None
        }
    }

    pub(crate) fn determine_cookie_domain(
        origin_config: &OriginConfig,
        is_local: bool,
    ) -> Option<String> {
        if is_local {
            return None;
        }

        let frontend_domain = origin_config.frontend_url.host_str().unwrap();
        let backend_domain = origin_config.rp_id();

        if Self::are_subdomains_of_same(frontend_domain, backend_domain) {
            if let Some(base_domain) = Self::get_base_domain(frontend_domain, backend_domain) {
                return Some(format!(".{}", base_domain));
            }
        }

        None
    }

    pub(crate) fn are_subdomains_of_same(domain1: &str, domain2: &str) -> bool {
        let domain1 = Self::normalize_domain(domain1);
        let domain2 = Self::normalize_domain(domain2);

        // if same, not subdomains
        if domain1 == domain2 {
            return false;
        }

        let parts1: Vec<&str> = domain1.split('.').collect();
        let parts2: Vec<&str> = domain2.split('.').collect();

        if parts1.len() < 2 || parts2.len() < 2 {
            return false;
        }

        let base1 = format!("{}.{}", parts1[parts1.len() - 2], parts1[parts1.len() - 1]);
        let base2 = format!("{}.{}", parts2[parts2.len() - 2], parts2[parts2.len() - 1]);

        base1 == base2
    }

    pub(crate) fn get_base_domain(domain1: &str, domain2: &str) -> Option<String> {
        let domain1 = Self::normalize_domain(domain1);
        let domain2 = Self::normalize_domain(domain2);

        let parts1: Vec<&str> = domain1.split('.').collect();
        let parts2: Vec<&str> = domain2.split('.').collect();

        if parts1.len() >= 2 && parts2.len() >= 2 {
            let base1 = format!("{}.{}", parts1[parts1.len() - 2], parts1[parts1.len() - 1]);
            let base2 = format!("{}.{}", parts2[parts2.len() - 2], parts2[parts2.len() - 1]);

            if base1 == base2 {
                return Some(base1);
            }
        }

        None
    }

    pub(crate) fn normalize_domain(domain: &str) -> String {
        domain.strip_prefix("www.").unwrap_or(domain).to_string()
    }
}
