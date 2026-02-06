use signet::auth::jwt::JwtConfig;

fn main() {
    let (private_key, public_key) = JwtConfig::generate_key_pair();

    println!("Add to your .env:");
    println!("JWT_PRIVATE_KEY={}", private_key);
    println!();
    println!("Public key (for other services):");
    println!("{}", public_key);
}
