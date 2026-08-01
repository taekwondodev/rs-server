use axum::body::Body;
use axum::http::{HeaderValue, Request, header};

use super::{extract_ip, extract_user_agent};

fn make_parts(headers: &[(&str, &str)]) -> axum::http::request::Parts {
    let mut builder = Request::builder().uri("/test").method("GET");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    builder.body(Body::empty()).unwrap().into_parts().0
}

#[test]
fn user_agent_present() {
    let parts = make_parts(&[("user-agent", "curl/8.0")]);
    assert_eq!(extract_user_agent(&parts).as_deref(), Some("curl/8.0"));
}

#[test]
fn user_agent_missing() {
    let parts = make_parts(&[]);
    assert_eq!(extract_user_agent(&parts), None);
}

#[test]
fn user_agent_non_utf8_ignored() {
    let mut parts = make_parts(&[]);
    parts.headers.insert(header::USER_AGENT, HeaderValue::from_bytes(&[0xff, 0xfe]).unwrap());
    assert_eq!(extract_user_agent(&parts), None);
}

#[cfg(not(feature = "gateway"))]
mod connect_info {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use axum::extract::ConnectInfo;

    use super::{extract_ip, make_parts};

    #[test]
    fn uses_connect_info_when_present() {
        let mut parts = make_parts(&[]);
        let addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 7), 51234));
        parts.extensions.insert(ConnectInfo(addr));

        assert_eq!(extract_ip(&parts), Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
    }

    #[test]
    fn none_when_connect_info_missing() {
        let parts = make_parts(&[]);
        assert_eq!(extract_ip(&parts), None);
    }

    #[test]
    fn ignores_x_real_ip_header_without_gateway_feature() {
        // Without the `gateway` feature, a client-supplied `x-real-ip` must
        // never be trusted — only `ConnectInfo` (the real TCP peer) counts.
        let parts = make_parts(&[("x-real-ip", "198.51.100.1")]);
        assert_eq!(extract_ip(&parts), None);
    }
}

#[cfg(feature = "gateway")]
mod trusted_proxy {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{extract_ip, make_parts};

    #[test]
    fn uses_x_real_ip_when_present() {
        let parts = make_parts(&[("x-real-ip", "198.51.100.1")]);
        assert_eq!(extract_ip(&parts), Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
    }

    #[test]
    fn none_when_header_missing() {
        let parts = make_parts(&[]);
        assert_eq!(extract_ip(&parts), None);
    }

    #[test]
    fn none_when_header_malformed() {
        let parts = make_parts(&[("x-real-ip", "not-an-ip")]);
        assert_eq!(extract_ip(&parts), None);
    }
}
