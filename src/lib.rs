//! This library was created based on [rfc6265](https://tools.ietf.org/html/rfc6265).
extern crate base64;
extern crate libsodium_sys;

// use libsodium_sys::crypto_aead_chacha20poly1305_encrypt as encrypt;
// use libsodium_sys::crypto_aead_chacha20poly1305_decrypt as decrypt;

pub struct Cookie {
    /// The name of this cookie
    name: String,
    /// The value of this cookie
    value: String,
    /// Indicates the maximum lifetime of the cookie.
    expires: Option<()>,
    /// Indicates the maximum lifetime of the cookie.
    max_age: Option<u64>,
    /// Specifies those hosts to which the cookie will be sent.
    domain: Option<String>,
    /// Sets the scope of each cookie to a set of paths.
    path: Option<String>,
    /// Sets the scope of the cookie to "secure" channels.
    secure: bool,
    /// Sets the scope of the cookie to HTTP requests only.
    httponly: bool,
}

impl Cookie {
    pub fn new(name: String, value: String) -> Cookie {
        Cookie {
            name: name,
            value: value,
            expires: None,
            max_age: None,
            domain: None,
            path: None,
            secure: false,
            httponly: false,
        }
    }

    /// Sets the `Expires` attribute of the cookie, indicating the maximum
    /// lifetime of the cookie. If both the `Expires` and `Max-Age` attributes
    /// are set, the `Max-Age` attribute has precedence. However, the `Max-Age`
    /// attribute is not supported by some user agents. See rfc6265 4.1.2.2 for
    /// more information.
    pub fn expires(&mut self, expires: ()) -> &mut Cookie {
        self.expires = Some(expires);
        self
    }

    /// Sets the `Max-Age` attribute of the cookie, indicating the maximum
    /// lifetime of the cookie, represented as the number of seconds until
    /// the cookie expires. If both the `Expires` and `Max-Age` attributes
    /// are set, the `Max-Age` attribute has precedence. However, the `Max-Age`
    /// attribute is not supported by some user agents. See rfc6265 4.1.2.2 for
    /// more information.
    pub fn max_age(&mut self, max_age: u64) -> &mut Cookie {
        self.max_age = Some(max_age);
        self
    }

    /// Sets the `Domain` attribute, specifying which hosts the cookie will
    /// be sent to by the User Agent.
    pub fn domain(&mut self, domain: String) -> &mut Cookie {
        self.domain = Some(domain);
        self
    }

    /// Sets the `Path` attribute, limiting the scope of the cookie to the
    /// given set of paths. This attribute cannot be relied upon for
    /// security. See rfc6265 4.1.2.4 for more information.
    pub fn path(&mut self, path: String) -> &mut Cookie {
        self.path = Some(path);
        self
    }

    /// Sets the `Secure` attribute, limiting the scope of the cookie to
    /// "secure" channels, such as HTTPS.
    pub fn secure(&mut self) -> &mut Cookie {
        self.secure = true;
        self
    }

    /// Sets the `HttpOnly` attribute, which limits the scope of the cookie to
    /// HTTP requests. As an example, this means that the cookie would not be
    /// exposed to scripts via a web browser API. This attribute is independent
    /// of the `Secure` attribute; a cookie can have both attributes.
    pub fn httponly(&mut self) -> &mut Cookie {
        self.httponly = true;
        self
    }

    /// Serialize this cookie for writing to a socket.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut cookie_bytes = String::new();
        let key = base64_encode(self.name.as_bytes());
        let value = base64_encode(self.name.as_bytes());
        cookie_bytes.push_str(&key);
        cookie_bytes.push('=');
        cookie_bytes.push_str(&value);
        cookie_bytes.into_bytes()
    }
}

fn base64_encode(input: &[u8]) -> String {
    use base64::Base64Mode;
    base64::encode_mode(input, Base64Mode::UrlSafe)
}

fn base64_decode(input: &str) -> Vec<u8> {
    use base64::Base64Mode;
    base64::decode_mode(input, Base64Mode::UrlSafe).unwrap()
}
