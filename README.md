# secret-fmt

![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)
![`no_std` compatible](https://img.shields.io/badge/no__std-compatible-brightgreen)

Accidental logging of PII (emails, IP addresses) or secrets (API keys, passwords) is a massive security liability.

**secret-fmt** provides a tiny, zero-dependency `#![no_std]` wrapper type called `Secret<T>` that prevents accidental logging by overriding `Debug` and `Display` to emit `"[REDACTED]"`. 

It has **zero trait bounds**, meaning you can wrap *any* third-party type instantly without having to write boilerplate.

## Usage

```rust
use secret_fmt::{Secret, redact};

// 1. Wrap your sensitive data
let my_secret: Secret<String> = "super_secret_api_token".to_string().into();

// 2. Accidental logging is safe!
println!("User token is: {}", my_secret);     // Prints: User token is: [REDACTED]
println!("Debug token is: {:?}", my_secret);  // Prints: Debug token is: [REDACTED]

// 3. Log inline references safely without ownership
let token = "sensitive_data";
println!("Inline redact: {}", redact!(&token)); // Prints: [REDACTED]

// 4. Access the data only when you actually need it
let actual_token: &String = my_secret.as_inner();
assert_eq!(actual_token, "super_secret_api_token");
```

### Serde Safety (Optional Feature)

Unlike other crates, `Secret<T>` **intentionally does not implement `Serialize` by default**. 
If a user serializes a database struct and the password field writes `"[REDACTED]"`, it causes data destruction. Instead, `secret-fmt` forces you to be explicit about how the data leaves your system using `#[serde(serialize_with)]`.

In `Cargo.toml`:
```toml
[dependencies]
secret-fmt = { version = "0.1", features = ["serde"] }
```

```rust
# #[cfg(feature = "serde")]
# fn main() {
use secret_fmt::{Secret, serialize_redacted, serialize_actual};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct UserResponse {
    id: u32,
    
    // Explicitly choose to redact this field when serialized to JSON
    #[serde(serialize_with = "serialize_redacted::serialize")]
    api_key: Secret<String>,
    
    // Explicitly choose to serialize the real underlying value for an upstream API
    #[serde(serialize_with = "serialize_actual::serialize")]
    pass_through: Secret<String>,
}

let incoming = r#"{"id": 123, "api_key": "real_token", "pass_through": "stripe_token"}"#;
let user: UserResponse = serde_json::from_str(incoming).unwrap();

// Outbound JSON explicitly enforces your chosen policies
let outbound = serde_json::to_string(&user).unwrap();
assert_eq!(outbound, r#"{"id":123,"api_key":"[REDACTED]","pass_through":"stripe_token"}"#);
# }
# #[cfg(not(feature = "serde"))]
# fn main() {}
```

## Why not `secrecy`?
The [secrecy](https://crates.io/crates/secrecy) crate is fantastic, but it enforces the `Zeroize` trait on everything it wraps to clear memory on drop. If you are dealing with types from external crates (like `reqwest::HeaderValue`), you have to write boilerplate wrappers to use `secrecy`. 

`Secret` makes no attempt to clear memory—it focuses exclusively on stopping string/log/JSON leakage. Because it drops the `Zeroize` requirement, it works instantly on *any* type out of the box with zero dependencies.
