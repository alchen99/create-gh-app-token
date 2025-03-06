use clap::Parser;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use serde::{Deserialize, Serialize};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to GitHub App's private key PEM file
    #[arg(short, long)]
    key_path: String,

    /// GitHub App ID
    #[arg(short, long)]
    app_id: String,

    /// GitHub App Installation ID
    #[arg(short, long)]
    installation_id: String,
}

#[derive(Debug, Serialize)]
struct JwtClaims {
    iat: u64,     // Issued at time
    exp: u64,     // Expiration time
    iss: String,  // Issuer (GitHub App ID)
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    token: String,
    expires_at: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    // Read private key from file
    let private_key = fs::read_to_string(&args.key_path)?;
    
    // Create JWT token for GitHub API authentication
    let jwt = create_jwt(&private_key, &args.app_id)?;
    
    // Exchange JWT for an installation token
    let token = get_installation_token(&jwt, &args.installation_id).await?;
    
    println!("Installation Token: {}", token.token);
    println!("Expires at: {}", token.expires_at);
    
    Ok(())
}

fn create_jwt(private_key: &str, app_id: &str) -> Result<String, Box<dyn std::error::Error>> {
    // Get current time and expiration (10 minutes from now)
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let expiration = now + 600; // 10 minutes from now
    
    let claims = JwtClaims {
        iat: now,
        exp: expiration,
        iss: app_id.to_string(),
    };
    
    // Create a JWT header specifying the RS256 algorithm
    let header = Header::new(Algorithm::RS256);
    
    // Create encoding key from private key
    let key = EncodingKey::from_rsa_pem(private_key.as_bytes())?;
    
    // Encode JWT
    let token = encode(&header, &claims, &key)?;
    
    Ok(token)
}

async fn get_installation_token(jwt: &str, installation_id: &str) -> Result<TokenResponse, Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    let url = format!(
        "https://api.github.com/app/installations/{}/access_tokens", 
        installation_id
    );
    
    let response = client
        .post(&url)
        .header(USER_AGENT, "rust-github-app-token-generator")
        .header(ACCEPT, "application/vnd.github.v3+json")
        .header(AUTHORIZATION, format!("Bearer {}", jwt))
        .send()
        .await?;
    
    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(format!("API error: {}", error_text).into());
    }
    
    let token_response = response.json::<TokenResponse>().await?;
    
    Ok(token_response)
}
