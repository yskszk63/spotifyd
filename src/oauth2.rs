use std::collections::HashMap;
use std::fs;

use librespot::core::authentication::Credentials;
use oauth2::basic::BasicTokenType;
use oauth2::EmptyExtraTokenFields;
use oauth2::StandardTokenResponse;
use oauth2::{
    basic::BasicClient, http::StatusCode, url::ParseError, AuthUrl, AuthorizationCode, ClientId,
    CsrfToken, HttpResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use tiny_http::{Response, Server};

const AUTHORIZATION_ENDPOINT: &str = "https://accounts.spotify.com/authorize";
const TOKEN_ENDPOINT: &str = "https://accounts.spotify.com/api/token";

pub(crate) fn get_credentials(
    client_id: &str,
    redirect_url: &str,
) -> Result<Credentials, ParseError> {
    let tokencache = xdg::BaseDirectories::with_prefix("spotifyd_oauth2")
        .unwrap()
        .place_cache_file("token")
        .unwrap();

    if let Ok(token) = fs::read_to_string(&tokencache) {
        let token_result = serde_json::from_str::<
            StandardTokenResponse<EmptyExtraTokenFields, BasicTokenType>,
        >(&token)
        .unwrap();
        // TODO refresh
        return Ok(Credentials {
            username: "".to_string(),
            auth_type: librespot::protocol::authentication::AuthenticationType::AUTHENTICATION_SPOTIFY_TOKEN,
            auth_data: token_result.access_token().secret().as_bytes().to_vec(),
        });
    }

    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        None,
        AuthUrl::new(AUTHORIZATION_ENDPOINT.to_string())?,
        Some(TokenUrl::new(TOKEN_ENDPOINT.to_string())?),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url.to_string())?);

    let (code_challenge, code_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("streaming".to_string()))
        .add_scope(Scope::new("user-read-email".to_string()))
        .add_scope(Scope::new("user-read-private".to_string()))
        .set_pkce_challenge(code_challenge)
        .url();

    println!("{}", auth_url);

    let server = Server::http("127.0.0.1:8080").unwrap(); // FIXME
    let mut code_state = None;
    for request in server.incoming_requests() {
        let url = request.url().to_string();
        request.respond(Response::new_empty(200.into())).unwrap();

        if let Some((_, query)) = url.split_once("?") {
            let query = url::form_urlencoded::parse(query.as_bytes());
            let query = query.into_iter().collect::<HashMap<_, _>>();
            if let (Some(code), Some(state)) = (query.get("code"), query.get("state")) {
                code_state = Some((code.to_string(), state.to_string()));
                break;
            }
        }
    }

    let (code, state) = code_state.unwrap();
    if &state != csrf_token.secret() {
        panic!("mismatch");
    }

    let token_result = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(code_verifier)
        .add_extra_param("client_id", client_id)
        .request::<_, minreq::Error>(|req| {
            println!("{:?}", req);
            let mut r = minreq::post(req.url).with_body(req.body);
            for (k, v) in req.headers {
                let k = k.unwrap().to_string();
                if k != "authorization" {
                    r = r.with_header(k, v.to_str().unwrap());
                }
            }
            let res = r.send()?;
            Ok(HttpResponse {
                status_code: StatusCode::from_u16(res.status_code as u16).unwrap(),
                headers: res
                    .headers
                    .iter()
                    .map(|(k, v)| (k.parse().unwrap(), v.parse().unwrap()))
                    .collect(),
                body: res.into_bytes(),
            })
        })
        .unwrap();

    fs::write(tokencache, serde_json::to_string(&token_result).unwrap()).unwrap();

    Ok(Credentials {
        username: "".to_string(),
        auth_type:
            librespot::protocol::authentication::AuthenticationType::AUTHENTICATION_SPOTIFY_TOKEN,
        auth_data: token_result.access_token().secret().as_bytes().to_vec(),
    })
}
