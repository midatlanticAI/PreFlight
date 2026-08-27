use jwt::Token;

pub fn subject(raw: &str) -> String {
    let token: Token<Header, Claims, _> = Token::parse_unverified(raw).unwrap();
    token.claims().sub.clone()
}
