//! This library was created based on [rfc6265](https://tools.ietf.org/html/rfc6265).
extern crate base64;
extern crate libsodium_sys;

// use libsodium_sys::crypto_aead_chacha20poly1305_encrypt as encrypt;
// use libsodium_sys::crypto_aead_chacha20poly1305_decrypt as decrypt;

#[derive(Clone, Debug, PartialEq)]
pub struct Cookie {
    /// The name of this cookie
    pub name: String,
    /// The value of this cookie
    pub value: String,
    /// Indicates the maximum lifetime of the cookie.
    pub expires: Option<String>,
    /// Indicates the maximum lifetime of the cookie.
    pub max_age: Option<u64>,
    /// Specifies those hosts to which the cookie will be sent.
    pub domain: Option<String>,
    /// Sets the scope of each cookie to a set of paths.
    pub path: Option<String>,
    /// Sets the scope of the cookie to "secure" channels.
    pub secure: bool,
    /// Sets the scope of the cookie to HTTP requests only.
    pub httponly: bool,
}

impl Cookie {
    pub fn new<S: Into<String>>(name: S, value: S) -> Cookie {
        let name = name.into();
        let value = value.into();
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
    /// lifetime of the cookie. The `Expires` attribute must correspond with
    /// rfc2616 3.2 date-times. If both the `Expires` and `Max-Age` attributes
    /// are set, the `Max-Age` attribute has precedence. However, the `Max-Age`
    /// attribute is not supported by some user agents. See rfc6265 4.1.2.2 for
    /// more information.
    pub fn expires(mut self, expires: String) -> Cookie {
        self.expires = Some(expires);
        self
    }

    /// Sets the `Max-Age` attribute of the cookie, indicating the maximum
    /// lifetime of the cookie, represented as the number of seconds until
    /// the cookie expires. If both the `Expires` and `Max-Age` attributes
    /// are set, the `Max-Age` attribute has precedence. However, the `Max-Age`
    /// attribute is not supported by some user agents. See rfc6265 4.1.2.2 for
    /// more information.
    pub fn max_age(mut self, max_age: u64) -> Cookie {
        self.max_age = Some(max_age);
        self
    }

    /// Sets the `Domain` attribute, specifying which hosts the cookie will
    /// be sent to by the User Agent.
    pub fn domain(mut self, domain: String) -> Cookie {
        self.domain = Some(domain);
        self
    }

    /// Sets the `Path` attribute, limiting the scope of the cookie to the
    /// given set of paths. This attribute cannot be relied upon for
    /// security. See rfc6265 4.1.2.4 for more information.
    pub fn path(mut self, path: String) -> Cookie {
        self.path = Some(path);
        self
    }

    /// Sets the `Secure` attribute, limiting the scope of the cookie to
    /// "secure" channels, such as HTTPS.
    pub fn secure(mut self) -> Cookie {
        self.secure = true;
        self
    }

    /// Sets the `HttpOnly` attribute, which limits the scope of the cookie to
    /// HTTP requests. As an example, this means that the cookie would not be
    /// exposed to scripts via a web browser API. This attribute is independent
    /// of the `Secure` attribute; a cookie can have both attributes.
    pub fn httponly(mut self) -> Cookie {
        self.httponly = true;
        self
    }

    /// Serialize this cookie for writing to a socket.
    pub fn as_bytes(&self) -> Vec<u8> {
        use std::fmt::Write;
        let mut cookie_bytes = String::new();
        // Write the name and value
        // We base64 encode the name and value to ensure
        // compatibility with user agents. One alternative is
        // to percent encode, but percent encoding takes more space.
        // let name = base64_encode(self.name.as_bytes());
        // let value = base64_encode(self.value.as_bytes());
        let name = &self.name;
        let value = &self.value;
        cookie_bytes.push_str(name);
        cookie_bytes.push('=');
        cookie_bytes.push_str(value);

        // Check for expires attribute
        if let Some(ref expires) = self.expires {
            cookie_bytes.push_str("; Expires=");
            cookie_bytes.push_str(expires);
        }

        // Check for max age attribute
        if let Some(age) = self.max_age {
            cookie_bytes.push_str("; Max-Age=");
            // TODO(nokaa): It's probably safe to unwrap here.
            write!(&mut cookie_bytes, "{}", age).unwrap();
        }

        // Check for domain attribute
        if let Some(ref domain) = self.domain {
            cookie_bytes.push_str("; Domain=");
            cookie_bytes.push_str(domain);
        }

        // Check for path attribute
        if let Some(ref path) = self.path {
            cookie_bytes.push_str("; Path=");
            cookie_bytes.push_str(path);
        }

        // Check for secure attribute
        if self.secure {
            cookie_bytes.push_str("; Secure");
        }

        // Check for httponly attribute
        if self.httponly {
            cookie_bytes.push_str("; HttpOnly");
        }

        cookie_bytes.into_bytes()
    }

    pub fn from_bytes(cookie_bytes: &[u8]) -> Cookie {
        let len = cookie_bytes.len();
        let mut name = String::new();
        let mut value = String::new();
        let mut i = 0;
        let mut in_name = true;
        while i < len {
            match cookie_bytes[i] {
                b'=' => in_name = false,
                b';' => {
                    // A cookie will have `; ` after the value
                    // if it contains other components.
                    i += 2;
                    break;
                }
                c => {
                    if in_name {
                        name.push(c as char);
                    } else {
                        value.push(c as char);
                    }
                }
            }
            i += 1;
        }

        // Decode from base64
        // let name = String::from_utf8(base64_decode(&name)).unwrap();
        // let value = String::from_utf8(base64_decode(&value)).unwrap();
        let mut cookie = Cookie::new(name, value);

        if i < len {
            let mut cookie_bytes = &cookie_bytes[i..];
            while !cookie_bytes.is_empty() {
                if cookie_bytes.starts_with(b"Expires=") {
                    cookie_bytes = &cookie_bytes[8..];
                    let split: Vec<&[u8]> = cookie_bytes.splitn(2, |b| *b == b';').collect();
                    let expires = String::from_utf8(split[0].to_owned()).unwrap();
                    cookie = cookie.expires(expires);
                    cookie_bytes = if split.len() == 1 {
                        &[]
                    } else {
                        &split[1][1..]
                    };
                } else if cookie_bytes.starts_with(b"Max-Age=") {
                    cookie_bytes = &cookie_bytes[8..];
                    let split: Vec<&[u8]> = cookie_bytes.splitn(2, |b| *b == b';').collect();
                    let max_age = String::from_utf8(split[0].to_owned()).unwrap();
                    cookie = cookie.max_age(u64::from_str_radix(&max_age, 10).unwrap());
                    cookie_bytes = if split.len() == 1 {
                        &[]
                    } else {
                        &split[1][1..]
                    };
                } else if cookie_bytes.starts_with(b"Domain=") {
                    cookie_bytes = &cookie_bytes[7..];
                    let split: Vec<&[u8]> = cookie_bytes.splitn(2, |b| *b == b';').collect();
                    let domain = String::from_utf8(split[0].to_owned()).unwrap();
                    cookie = cookie.domain(domain);
                    cookie_bytes = if split.len() == 1 {
                        &[]
                    } else {
                        &split[1][1..]
                    };
                } else if cookie_bytes.starts_with(b"Path=") {
                    cookie_bytes = &cookie_bytes[5..];
                    let split: Vec<&[u8]> = cookie_bytes.splitn(2, |b| *b == b';').collect();
                    let path = String::from_utf8(split[0].to_owned()).unwrap();
                    cookie = cookie.path(path);
                    cookie_bytes = if split.len() == 1 {
                        &[]
                    } else {
                        &split[1][1..]
                    };
                } else if cookie_bytes.starts_with(b"Secure") {
                    cookie_bytes = &cookie_bytes[6..];
                    let split: Vec<&[u8]> = cookie_bytes.splitn(2, |b| *b == b';').collect();
                    cookie = cookie.secure();
                    cookie_bytes = if split.len() == 1 {
                        &[]
                    } else {
                        &split[1][1..]
                    };
                } else if cookie_bytes.starts_with(b"HttpOnly") {
                    cookie_bytes = &cookie_bytes[8..];
                    let split: Vec<&[u8]> = cookie_bytes.splitn(2, |b| *b == b';').collect();
                    cookie = cookie.httponly();
                    cookie_bytes = if split.len() == 1 {
                        &[]
                    } else {
                        &split[1][1..]
                    };
                }
            }
        }

        cookie
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
