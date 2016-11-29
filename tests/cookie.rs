extern crate base64;
extern crate cookie;

use cookie::Cookie;

#[test]
fn simple_cookie_bytes() {
    let name_b64 = base64_encode(b"name");
    let value_b64 = base64_encode(b"value");
    let cookie_bytes = format!("{}={}", name_b64, value_b64).into_bytes();
    let cookie = Cookie::new("name", "value");
    assert_eq!(Cookie::from_bytes(&cookie_bytes), cookie);
    assert_eq!(cookie_bytes, cookie.as_bytes());
}

fn base64_encode(input: &[u8]) -> String {
    use base64::Base64Mode;
    base64::encode_mode(input, Base64Mode::UrlSafe)
}

fn base64_decode(input: &str) -> Vec<u8> {
    use base64::Base64Mode;
    base64::decode_mode(input, Base64Mode::UrlSafe).unwrap()
}
