use super::super::cookie::*;
use crate::config::origin::OriginConfig;
use axum_extra::extract::cookie::SameSite;

fn create_test_origin_config(frontend_url: &str, backend_domain: &str) -> OriginConfig {
    OriginConfig {
        frontend_origin: frontend_url.to_string(),
        frontend_url: url::Url::parse(frontend_url).unwrap(),
        backend_domain: backend_domain.into(),
    }
}

#[test]
fn test_determine_same_site_https() {
    let same_site = CookieService::determine_same_site(true, false);
    assert_eq!(same_site, SameSite::Strict);
}

#[test]
fn test_determine_same_site_http_local() {
    let same_site = CookieService::determine_same_site(false, true);
    assert_eq!(same_site, SameSite::Lax);
}

#[test]
fn test_determine_same_site_http_non_local() {
    let same_site = CookieService::determine_same_site(false, false);
    assert_eq!(same_site, SameSite::None);
}

#[test]
fn test_normalize_domain_with_www() {
    let normalized = CookieService::normalize_domain("www.example.com");
    assert_eq!(normalized, "example.com");
}

#[test]
fn test_normalize_domain_without_www() {
    let normalized = CookieService::normalize_domain("example.com");
    assert_eq!(normalized, "example.com");
}

#[test]
fn test_normalize_domain_subdomain_with_www() {
    let normalized = CookieService::normalize_domain("www.api.example.com");
    assert_eq!(normalized, "api.example.com");
}

#[test]
fn test_are_subdomains_of_same_valid() {
    let result = CookieService::are_subdomains_of_same("api.example.com", "app.example.com");
    assert!(result);
}

#[test]
fn test_are_subdomains_of_same_with_www() {
    let result =
        CookieService::are_subdomains_of_same("www.api.example.com", "www.app.example.com");
    assert!(result);
}

#[test]
fn test_are_subdomains_of_same_mixed_www() {
    let result = CookieService::are_subdomains_of_same("www.example.com", "api.example.com");
    assert!(result);
}

#[test]
fn test_are_subdomains_of_same_identical_domains() {
    let result = CookieService::are_subdomains_of_same("example.com", "example.com");
    assert!(!result);
}

#[test]
fn test_are_subdomains_of_same_different_base() {
    let result = CookieService::are_subdomains_of_same("api.example.com", "app.different.com");
    assert!(!result);
}

#[test]
fn test_are_subdomains_of_same_single_part_domain() {
    let result = CookieService::are_subdomains_of_same("localhost", "example.com");
    assert!(!result);
}

#[test]
fn test_are_subdomains_of_same_base_vs_subdomain() {
    let result = CookieService::are_subdomains_of_same("example.com", "api.example.com");
    assert!(result);
}

#[test]
fn test_get_base_domain_valid() {
    let base = CookieService::get_base_domain("api.example.com", "app.example.com");
    assert_eq!(base, Some("example.com".to_string()));
}

#[test]
fn test_get_base_domain_with_www() {
    let base = CookieService::get_base_domain("www.api.example.com", "www.app.example.com");
    assert_eq!(base, Some("example.com".to_string()));
}

#[test]
fn test_get_base_domain_different_bases() {
    let base = CookieService::get_base_domain("api.example.com", "app.different.com");
    assert_eq!(base, None);
}

#[test]
fn test_get_base_domain_single_part() {
    let base = CookieService::get_base_domain("localhost", "example.com");
    assert_eq!(base, None);
}

#[test]
fn test_get_base_domain_three_level_subdomain() {
    let base = CookieService::get_base_domain("v1.api.example.com", "v2.api.example.com");
    assert_eq!(base, Some("example.com".to_string()));
}

#[test]
fn test_cookie_service_new_https_production() {
    let origin_config = create_test_origin_config("https://app.example.com", "api.example.com");
    let cookie_service = CookieService::new(&origin_config);

    assert!(cookie_service.secure);
    assert_eq!(cookie_service.same_site, SameSite::Strict);
    assert_eq!(cookie_service.path, "/auth");
    assert!(cookie_service.http_only);
}

#[test]
fn test_cookie_service_new_http_localhost() {
    let origin_config = create_test_origin_config("http://localhost:3000", "localhost");
    let cookie_service = CookieService::new(&origin_config);

    assert!(!cookie_service.secure);
    assert_eq!(cookie_service.same_site, SameSite::Lax);
    assert_eq!(cookie_service.domain, None);
}

#[test]
fn test_cookie_service_new_http_127() {
    let origin_config = create_test_origin_config("http://127.0.0.1:3000", "127.0.0.1");
    let cookie_service = CookieService::new(&origin_config);

    assert!(!cookie_service.secure);
    assert_eq!(cookie_service.domain, None);
}

#[test]
fn test_determine_cookie_domain_localhost() {
    let origin_config = create_test_origin_config("http://localhost:3000", "localhost");
    let domain = CookieService::determine_cookie_domain(&origin_config, true);
    assert_eq!(domain, None);
}

#[test]
fn test_determine_cookie_domain_subdomains() {
    let origin_config = create_test_origin_config("https://app.example.com", "api.example.com");
    let domain = CookieService::determine_cookie_domain(&origin_config, false);
    assert_eq!(domain, Some(".example.com".to_string()));
}

#[test]
fn test_determine_cookie_domain_different_domains() {
    let origin_config = create_test_origin_config("https://app.example.com", "different.com");
    let domain = CookieService::determine_cookie_domain(&origin_config, false);
    assert_eq!(domain, None);
}

#[test]
fn test_determine_cookie_domain_same_domain() {
    let origin_config = create_test_origin_config("https://example.com", "example.com");
    let domain = CookieService::determine_cookie_domain(&origin_config, false);
    assert_eq!(domain, None);
}

#[test]
fn test_create_refresh_token_cookie() {
    let origin_config = create_test_origin_config("https://app.example.com", "api.example.com");
    let cookie_service = CookieService::new(&origin_config);

    let cookie = cookie_service.create_refresh_token_cookie("test_token_value");

    assert_eq!(cookie.name(), "refresh_token");
    assert_eq!(cookie.value(), "test_token_value");
    assert_eq!(cookie.path(), Some("/auth"));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Strict));
}

#[test]
fn test_clear_refresh_token_cookie() {
    let origin_config = create_test_origin_config("https://app.example.com", "api.example.com");
    let cookie_service = CookieService::new(&origin_config);

    let cookie = cookie_service.clear_refresh_token_cookie();

    assert_eq!(cookie.name(), "refresh_token");
    assert_eq!(cookie.value(), "");
    assert!(cookie.max_age().is_some());
}
