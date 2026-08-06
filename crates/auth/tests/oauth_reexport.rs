use std::str::FromStr;

#[test]
fn oauth_paths_survive_the_crate_split() {
    let via_module = ferrlabs_auth::oauth::OAuthProvider::Discord;
    let via_root = ferrlabs_auth::OAuthProvider::from_str("discord").unwrap();
    assert_eq!(via_module, via_root);

    let client =
        ferrlabs_auth::OAuthClient::new(via_root, "id", "secret", "https://example.com/cb", None);
    assert_eq!(client.provider().as_str(), "discord");
}
