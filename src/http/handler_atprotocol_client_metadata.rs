//! Handles GET /oauth-client-metadata.json - Provides ATProtocol OAuth client metadata per RFC 7591

use atproto_oauth_axum::{handler_metadata::handle_oauth_metadata, state::OAuthClientConfig};
use axum::{extract::State, response::IntoResponse};

use super::context::AppState;
use crate::config::{ATPROTO_CLIENT_METADATA_PATH, OAuthSupportedScopes};

fn atprotocol_metadata_scope(supported_scopes: &OAuthSupportedScopes) -> Option<String> {
    let all_scopes = supported_scopes.as_ref().clone();
    let filtered_scopes =
        crate::oauth::scope_validation::filter_atprotocol_scopes(&all_scopes).unwrap_or_default();

    let mut scope_tokens: Vec<String> = filtered_scopes
        .iter()
        .map(|scope| scope.to_string_normalized())
        .collect();
    scope_tokens.extend(
        supported_scopes
            .as_strings()
            .into_iter()
            .filter(|scope| scope.starts_with("include:")),
    );

    if scope_tokens.is_empty() {
        None
    } else {
        Some(scope_tokens.join(" "))
    }
}

/// Handles requests for ATProtocol OAuth client metadata.
///
/// This endpoint provides client metadata required for ATProtocol OAuth flows,
/// conforming to RFC 7591 client metadata specification.
pub async fn handle_atpoauth_client_metadata(
    State(app_state): State<AppState>,
) -> impl IntoResponse {
    let oauth_client_config = OAuthClientConfig {
        client_id: format!(
            "{}{}",
            app_state.config.external_base, ATPROTO_CLIENT_METADATA_PATH
        ),
        redirect_uris: format!("{}/oauth/atp/callback", app_state.config.external_base),
        jwks_uri: None, // Use inline JWKS instead of external URI
        signing_keys: app_state.atproto_oauth_signing_keys.clone(),
        client_name: Some(app_state.config.atproto_client_name.as_ref().clone()),
        client_uri: Some(app_state.config.external_base.clone()),
        logo_uri: app_state.config.atproto_client_logo.as_ref().clone(),
        tos_uri: app_state.config.atproto_client_tos.as_ref().clone(),
        policy_uri: app_state.config.atproto_client_policy.as_ref().clone(),
        scope: atprotocol_metadata_scope(&app_state.config.oauth_supported_scopes),
    };

    // Use the atproto-oauth-axum handler
    handle_oauth_metadata(oauth_client_config).await
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_PERMISSION_SET: &str =
        "include:tools.example.read?aud=did:web:api.example.com#appview";

    #[test]
    fn test_atprotocol_metadata_scope_preserves_include_only_config() {
        let supported_scopes =
            OAuthSupportedScopes::try_from(format!("openid {EXAMPLE_PERMISSION_SET}")).unwrap();

        assert_eq!(
            atprotocol_metadata_scope(&supported_scopes),
            Some(EXAMPLE_PERMISSION_SET.to_string())
        );
    }

    #[test]
    fn test_atprotocol_metadata_scope_does_not_invent_atproto() {
        let supported_scopes =
            OAuthSupportedScopes::try_from("openid profile email".to_string()).unwrap();

        assert_eq!(atprotocol_metadata_scope(&supported_scopes), None);
    }

    #[test]
    fn test_atprotocol_metadata_scope_includes_known_and_raw_atprotocol_scopes() {
        let supported_scopes =
            OAuthSupportedScopes::try_from(format!("openid atproto {EXAMPLE_PERMISSION_SET}"))
                .unwrap();

        assert_eq!(
            atprotocol_metadata_scope(&supported_scopes),
            Some(format!("atproto {EXAMPLE_PERMISSION_SET}"))
        );
    }
}
