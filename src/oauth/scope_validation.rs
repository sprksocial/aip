//! OAuth scope validation utilities for AT Protocol scopes.

use crate::errors::OAuthError;
use atproto_oauth::scopes::Scope;
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone)]
pub struct ParsedScopeSet {
    known_scopes: Vec<Scope>,
    raw_scopes: Vec<String>,
    normalized_scopes: HashSet<String>,
}

impl ParsedScopeSet {
    pub fn known_scopes(&self) -> &[Scope] {
        &self.known_scopes
    }

    pub fn raw_scopes(&self) -> &[String] {
        &self.raw_scopes
    }

    pub fn normalized_scopes(&self) -> &HashSet<String> {
        &self.normalized_scopes
    }

    pub fn as_strings(&self) -> Vec<String> {
        let mut scopes: Vec<String> = self
            .known_scopes
            .iter()
            .map(|scope| scope.to_string_normalized())
            .collect();
        scopes.extend(self.raw_scopes.iter().cloned());
        scopes
    }
}

pub fn compat_scopes(scopes: &str) -> String {
    scopes
        .split_whitespace()
        .map(|token| token.strip_prefix("atproto:").unwrap_or(token))
        .collect::<Vec<_>>()
        .join(" ")
}

fn decode_scope_component(value: &str) -> String {
    let query = format!("v={value}");
    url::form_urlencoded::parse(query.as_bytes())
        .next()
        .map(|(_, decoded)| decoded.into_owned())
        .unwrap_or_default()
}

fn encode_scope_component(value: &str, reserved: &[char]) -> String {
    let mut encoded = String::with_capacity(value.len());

    for ch in value.chars() {
        if ch.is_ascii_whitespace() || ch == '%' || ch == '+' || reserved.contains(&ch) {
            encoded.push_str(&format!("%{:02X}", ch as u32));
        } else {
            encoded.push(ch);
        }
    }

    encoded
}

fn canonicalize_permission_set_scope(token: &str) -> Result<Option<String>, OAuthError> {
    let Some(remainder) = token.strip_prefix("include") else {
        return Ok(None);
    };

    if remainder.is_empty() {
        return Err(OAuthError::InvalidScope(
            "Permission-set scopes must include an NSID after 'include'".to_string(),
        ));
    }

    let (positional_nsid, query) = if let Some(suffix) = remainder.strip_prefix(':') {
        let (positional, query) = match suffix.split_once('?') {
            Some((positional, query)) => (positional, Some(query)),
            None => (suffix, None),
        };
        (Some(positional), query)
    } else if let Some(query) = remainder.strip_prefix('?') {
        (None, Some(query))
    } else {
        return Ok(None);
    };

    let positional_nsid = positional_nsid
        .filter(|nsid| !nsid.is_empty())
        .map(decode_scope_component);

    let mut params = BTreeMap::<String, Vec<String>>::new();
    if let Some(query) = query {
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            params
                .entry(key.into_owned())
                .or_default()
                .push(value.into_owned());
        }
    }

    let mut nsid_values = params.remove("nsid").unwrap_or_default();
    nsid_values.sort();
    nsid_values.dedup();

    let nsid = match (positional_nsid, nsid_values.as_slice()) {
        (Some(nsid), []) => nsid,
        (Some(nsid), [query_nsid]) if nsid == *query_nsid => nsid,
        (Some(_), [_]) | (Some(_), [_, ..]) => {
            return Err(OAuthError::InvalidScope(
                "Permission-set scopes cannot specify conflicting NSIDs".to_string(),
            ));
        }
        (None, [query_nsid]) => query_nsid.clone(),
        (None, []) => {
            return Err(OAuthError::InvalidScope(
                "Permission-set scopes must include an NSID after 'include'".to_string(),
            ));
        }
        (None, [_, ..]) => {
            return Err(OAuthError::InvalidScope(
                "Permission-set scopes cannot specify multiple NSIDs".to_string(),
            ));
        }
    };

    let nsid = encode_scope_component(&nsid, &['?']);
    let mut canonical = format!("include:{nsid}");

    let mut serialized_params = Vec::new();
    for (key, values) in params {
        let mut values = values;
        values.sort();
        values.dedup();

        for value in values {
            let key = encode_scope_component(&key, &['&', '=', '?']);
            let value = encode_scope_component(&value, &['&', '=', '?']);
            serialized_params.push(format!("{key}={value}"));
        }
    }

    if !serialized_params.is_empty() {
        canonical.push('?');
        canonical.push_str(&serialized_params.join("&"));
    }

    Ok(Some(canonical))
}

pub fn parse_scope_set(scope: &str) -> Result<ParsedScopeSet, OAuthError> {
    let normalized_input = compat_scopes(scope);
    let mut known_scope_tokens = Vec::new();
    let mut raw_scopes = Vec::new();
    let mut seen_raw_scopes = HashSet::new();

    for token in normalized_input.split_whitespace() {
        if let Some(canonical_permission_set) = canonicalize_permission_set_scope(token)? {
            if seen_raw_scopes.insert(canonical_permission_set.clone()) {
                raw_scopes.push(canonical_permission_set);
            }
            continue;
        }

        known_scope_tokens.push(token);
    }

    let known_scopes = Scope::parse_multiple_reduced(&known_scope_tokens.join(" "))
        .map_err(|e| OAuthError::InvalidScope(format!("Invalid scope format: {}", e)))?;

    let mut normalized_scopes: HashSet<String> = known_scopes
        .iter()
        .map(|scope| scope.to_string_normalized())
        .collect();
    normalized_scopes.extend(raw_scopes.iter().cloned());

    Ok(ParsedScopeSet {
        known_scopes,
        raw_scopes,
        normalized_scopes,
    })
}

pub fn serialize_atprotocol_scope_set(
    parsed_scopes: &ParsedScopeSet,
) -> Result<String, OAuthError> {
    let filtered_scopes: Vec<Scope> = parsed_scopes
        .known_scopes()
        .iter()
        .filter(|scope| !matches!(scope, Scope::OpenId | Scope::Profile | Scope::Email))
        .cloned()
        .collect();
    let mut serialized_scopes: Vec<String> = filtered_scopes
        .iter()
        .map(|scope| scope.to_string_normalized())
        .collect();

    serialized_scopes.extend(parsed_scopes.raw_scopes().iter().cloned());

    if serialized_scopes.is_empty() {
        return Err(OAuthError::InvalidScope(
            "No valid AT Protocol scopes remain after filtering".to_string(),
        ));
    }

    Ok(serialized_scopes.join(" "))
}

/// Filter AT Protocol scopes for the ATProtocol OAuth flow.
///
/// This function:
/// - Removes standard OAuth scopes (openid, profile, email) that are not used in AT Protocol
/// - Preserves all AT Protocol specific scopes
/// - Returns an error if required scopes are missing
pub fn filter_atprotocol_scopes(scopes: &[Scope]) -> Result<Vec<Scope>, OAuthError> {
    // Filter out OpenID Connect scopes, keeping only AT Protocol scopes
    let filtered: Vec<Scope> = scopes
        .iter()
        .filter(|s| !matches!(s, Scope::OpenId | Scope::Profile | Scope::Email))
        .cloned()
        .collect();

    // Ensure we have at least the atproto scope after filtering
    if filtered.is_empty() {
        return Err(OAuthError::InvalidScope(
            "No valid AT Protocol scopes remain after filtering".to_string(),
        ));
    }

    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atproto_oauth::scopes::TransitionScope;

    const EXAMPLE_PERMISSION_SET: &str =
        "include:tools.example.read?aud=did:web:api.example.com#appview";
    const EXAMPLE_PERMISSION_AUDIENCE: &str = "did:web:api.example.com#appview";

    #[test]
    fn test_filter_atprotocol_scopes() {
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,
            Scope::Profile,
            Scope::Email,
            Scope::Transition(TransitionScope::Generic),
            Scope::Transition(TransitionScope::Email),
        ];

        let result = filter_atprotocol_scopes(&scopes);
        assert!(result.is_ok());

        let filtered = result.unwrap();
        assert_eq!(filtered.len(), 3); // atproto, transition:generic, transition:email
        assert!(filtered.contains(&Scope::Atproto));
        assert!(filtered.contains(&Scope::Transition(TransitionScope::Generic)));
        assert!(filtered.contains(&Scope::Transition(TransitionScope::Email)));
        assert!(!filtered.contains(&Scope::OpenId));
        assert!(!filtered.contains(&Scope::Profile));
        assert!(!filtered.contains(&Scope::Email));
    }

    #[test]
    fn test_filter_fails_on_invalid_scopes() {
        let scopes = vec![Scope::OpenId, Scope::Profile, Scope::Email];

        let result = filter_atprotocol_scopes(&scopes);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_scope_set_supports_permission_sets() {
        let result = parse_scope_set(&format!("atproto {EXAMPLE_PERMISSION_SET}")).unwrap();

        assert_eq!(result.known_scopes(), &[Scope::Atproto]);
        assert_eq!(result.raw_scopes(), &[EXAMPLE_PERMISSION_SET.to_string()]);
        assert!(result.normalized_scopes().contains("atproto"));
        assert!(result.normalized_scopes().contains(EXAMPLE_PERMISSION_SET));
        assert_eq!(
            result.as_strings(),
            vec!["atproto".to_string(), EXAMPLE_PERMISSION_SET.to_string(),]
        );
    }

    #[test]
    fn test_parse_scope_set_supports_permission_set_query_form() {
        let result = parse_scope_set(
            &format!("atproto include?nsid=tools.example.read&aud={EXAMPLE_PERMISSION_AUDIENCE}")
                .replace('#', "%23"),
        )
        .unwrap();

        assert_eq!(result.known_scopes(), &[Scope::Atproto]);
        assert_eq!(result.raw_scopes(), &[EXAMPLE_PERMISSION_SET.to_string()]);
        assert!(result.normalized_scopes().contains(EXAMPLE_PERMISSION_SET));
    }

    #[test]
    fn test_parse_scope_set_canonicalizes_equivalent_permission_set_scopes() {
        let colon_form = parse_scope_set(&format!("atproto {EXAMPLE_PERMISSION_SET}")).unwrap();
        let query_form = parse_scope_set(
            &format!("atproto include?nsid=tools.example.read&aud={EXAMPLE_PERMISSION_AUDIENCE}")
                .replace('#', "%23"),
        )
        .unwrap();

        assert_eq!(colon_form.raw_scopes(), query_form.raw_scopes());
        assert_eq!(
            colon_form.normalized_scopes(),
            query_form.normalized_scopes()
        );
    }

    #[test]
    fn test_compat_scopes_only_strips_legacy_scope_prefixes() {
        let normalized = compat_scopes(
            "atproto:repo:* include?nsid=foo.bar&aud=did:web:example.com%23atproto:client",
        );

        assert_eq!(
            normalized,
            "repo:* include?nsid=foo.bar&aud=did:web:example.com%23atproto:client"
        );
    }

    #[test]
    fn test_parse_scope_set_preserves_atproto_inside_permission_set_values() {
        let result = parse_scope_set(
            "atproto include?nsid=foo.bar&aud=did:web:example.com%23atproto:client",
        )
        .unwrap();

        assert_eq!(result.known_scopes(), &[Scope::Atproto]);
        assert_eq!(
            result.raw_scopes(),
            &["include:foo.bar?aud=did:web:example.com#atproto:client".to_string()]
        );
    }

    #[test]
    fn test_parse_scope_set_preserves_plus_in_permission_set_values() {
        let parsed =
            parse_scope_set("atproto include?nsid=foo.bar&aud=did:web:example.com%23app%2Bview")
                .unwrap();

        assert_eq!(parsed.known_scopes(), &[Scope::Atproto]);
        assert_eq!(
            parsed.raw_scopes(),
            &["include:foo.bar?aud=did:web:example.com#app%2Bview".to_string()]
        );

        let serialized = serialize_atprotocol_scope_set(&parsed).unwrap();
        assert_eq!(
            serialized,
            "atproto include:foo.bar?aud=did:web:example.com#app%2Bview"
        );

        let reparsed = parse_scope_set(&serialized).unwrap();
        assert_eq!(reparsed.raw_scopes(), parsed.raw_scopes());
    }

    #[test]
    fn test_parse_scope_set_rejects_permission_set_without_nsid() {
        let result = parse_scope_set(&format!(
            "atproto include?aud={EXAMPLE_PERMISSION_AUDIENCE}"
        ));
        assert!(result.is_err());
        if let Err(error) = result {
            assert!(error.to_string().contains("NSID"));
        }
    }

    #[test]
    fn test_parse_scope_set_reduces_known_scopes_across_tokens() {
        let result = parse_scope_set("atproto repo:* repo:tools.example.record").unwrap();

        assert_eq!(result.known_scopes().len(), 2);
        assert!(result.normalized_scopes().contains("atproto"));
        assert!(result.normalized_scopes().contains("repo:*"));
        assert!(
            !result
                .normalized_scopes()
                .contains("repo:tools.example.record")
        );
        assert_eq!(
            result.as_strings(),
            vec!["atproto".to_string(), "repo:*".to_string()]
        );
    }

    #[test]
    fn test_serialize_atprotocol_scope_set_preserves_permission_sets() {
        let parsed = parse_scope_set(&format!("openid atproto {EXAMPLE_PERMISSION_SET}")).unwrap();

        let serialized = serialize_atprotocol_scope_set(&parsed).unwrap();
        assert_eq!(serialized, format!("atproto {EXAMPLE_PERMISSION_SET}"));
    }

    #[test]
    fn test_serialize_atprotocol_scope_set_allows_permission_set_only() {
        let parsed = parse_scope_set(EXAMPLE_PERMISSION_SET).unwrap();

        let serialized = serialize_atprotocol_scope_set(&parsed).unwrap();
        assert_eq!(serialized, EXAMPLE_PERMISSION_SET);
    }

    #[test]
    fn test_serialize_atprotocol_scope_set_allows_oidc_with_permission_set() {
        let parsed =
            parse_scope_set(&format!("openid profile email {EXAMPLE_PERMISSION_SET}")).unwrap();

        let serialized = serialize_atprotocol_scope_set(&parsed).unwrap();
        assert_eq!(serialized, EXAMPLE_PERMISSION_SET);
    }
}
