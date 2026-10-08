//! atproto identifier syntax, mirroring @atproto/syntax.

/// Dot-separated labels of 1-63 [A-Za-z0-9-], none starting or ending with
/// '-', at least `min` of them, `max_len` chars in all.
fn labels(s: &str, min: usize, max_len: usize) -> Option<Vec<&str>> {
    if s.len() > max_len || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
        return None;
    }
    let labels: Vec<&str> = s.split('.').collect();
    let ok = labels.len() >= min
        && labels.iter().all(|l| !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-'));
    ok.then_some(labels)
}

/// The authority may not start with a digit; the name is alphanumeric and
/// starts with a letter.
pub fn valid_nsid(s: &str) -> bool {
    let Some(parts) = labels(s, 3, 253 + 1 + 63) else {
        return false;
    };
    let name = parts[parts.len() - 1];
    !parts[0].as_bytes()[0].is_ascii_digit()
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name.bytes().all(|b| b.is_ascii_alphanumeric())
}

pub fn valid_rkey(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 512
        && s != "."
        && s != ".."
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:~-".contains(&b))
}

pub fn valid_record_path(path: &str) -> bool {
    path.split_once('/').is_some_and(|(c, r)| valid_nsid(c) && valid_rkey(r))
}

/// Handles under these can't be resolved publicly (reference
/// DISALLOWED_TLDS).
pub fn disallowed_handle_tld(h: &str) -> bool {
    const DISALLOWED_TLDS: &[&str] =
        &[".local", ".arpa", ".invalid", ".localhost", ".internal", ".example", ".alt", ".onion"];
    DISALLOWED_TLDS.iter().any(|t| h.ends_with(t))
}

/// The TLD starts with a letter.
pub fn valid_handle(h: &str) -> bool {
    labels(h, 2, 253).is_some_and(|l| l[l.len() - 1].as_bytes()[0].is_ascii_alphabetic())
}

pub fn valid_tid(s: &str) -> bool {
    s.len() == 13
        && b"234567abcdefghij".contains(&s.as_bytes()[0])
        && s.bytes().all(|b| b"234567abcdefghijklmnopqrstuvwxyz".contains(&b))
}

pub fn valid_did(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("did:") else {
        return false;
    };
    let Some((method, id)) = rest.split_once(':') else {
        return false;
    };
    s.len() <= 2048
        && !method.is_empty()
        && method.bytes().all(|b| b.is_ascii_lowercase())
        && !id.is_empty()
        && !id.ends_with(':')
        && !id.ends_with('%')
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"._:%-".contains(&b))
}

/// A space URI without its fragment: `at://{space DID}/space/{space type
/// NSID}/{skey}`, plus `/{author DID}/{collection}/{rkey}` for a record in
/// it (@atproto/syntax `parseSpaceAtUriString`, strict). Both DIDs must be
/// DIDs, not handles, and the skey follows the record-key syntax.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpaceUri<'a> {
    pub authority: &'a str,
    pub space_type: &'a str,
    pub skey: &'a str,
    /// (author, collection, rkey)
    pub record: Option<(&'a str, &'a str, &'a str)>,
}

pub fn parse_space_uri(s: &str) -> Option<SpaceUri<'_>> {
    let mut parts = s.strip_prefix("at://")?.split('/');
    let (authority, marker, space_type, skey) = (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
    let record = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (None, ..) => None,
        (Some(a), Some(c), Some(r), None) => Some((a, c, r)),
        _ => return None,
    };
    let ok = marker == "space"
        && valid_did(authority)
        && valid_nsid(space_type)
        && valid_rkey(skey)
        && record.is_none_or(|(a, c, r)| valid_did(a) && valid_nsid(c) && valid_rkey(r));
    ok.then_some(SpaceUri { authority, space_type, skey, record })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nsids() {
        for ok in ["app.bsky.feed.post", "com.example.fooBar", "a-0.b-1.c", "com.example.f00"] {
            assert!(valid_nsid(ok), "{ok}");
        }
        for bad in [
            "app.bsky",
            "1com.example.foo",
            "com.example.foo-bar",
            "com..foo",
            "com.example.3foo",
            "com.exa_mple.foo",
            "-com.example.foo",
        ] {
            assert!(!valid_nsid(bad), "{bad}");
        }
    }

    #[test]
    fn rkeys() {
        for ok in ["3jui7kd54zh2y", "self", "a:b~c_d.e-f", "..."] {
            assert!(valid_rkey(ok), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a b", "#x", &"a".repeat(513)] {
            assert!(!valid_rkey(bad), "{bad}");
        }
    }

    #[test]
    fn handles() {
        assert!(valid_handle("alice.bsky.social"));
        assert!(valid_handle("x.test"));
        assert!(!valid_handle("alice"));
        assert!(!valid_handle("alice.-bsky.social"));
        assert!(!valid_handle("alice.bsky.1social"));
        assert!(!valid_handle("al_ice.bsky.social"));
    }

    #[test]
    fn dids_tids() {
        assert!(valid_did("did:plc:abc123"));
        assert!(valid_did("did:web:example.com"));
        assert!(!valid_did("did:PLC:abc"));
        assert!(!valid_did("did:plc:"));
        assert!(valid_tid("3jui7kd54zh2y"));
        assert!(!valid_tid("3jui7kd54zh2"));
    }
}
