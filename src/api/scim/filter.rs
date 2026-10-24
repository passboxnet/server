//! A SCIM filter subset (RFC 7644 §3.4.2.2): `eq`, `ne`, `co`, `sw`, `ew`,
//! `pr`, `gt`/`ge`/`lt`/`le` on strings, `and`, `or`, `not` and
//! parentheses. Enough for what Okta, Microsoft Entra ID, OneLogin,
//! JumpCloud and Authentik send (`userName eq "x"`, `externalId eq "y"`,
//! `displayName eq "z"`, `members[value eq "id"]` paths are handled by
//! PATCH, not here).

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Str(String),
    Bool(bool),
    Null,
    Number(f64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    Compare {
        attr: String,
        op: String,
        value: Value,
    },
    Present(String),
    And(Box<Filter>, Box<Filter>),
    Or(Box<Filter>, Box<Filter>),
    Not(Box<Filter>),
}

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Word(String),
    Str(String),
    Open,
    Close,
}

fn tokenize(input: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let mut chars = input.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            c if c.is_whitespace() => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(Token::Open);
            }
            ')' => {
                chars.next();
                tokens.push(Token::Close);
            }
            '"' => {
                chars.next();
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some('\\') => match chars.next() {
                            Some(escaped) => value.push(escaped),
                            None => return Err("unterminated string".into()),
                        },
                        Some('"') => break,
                        Some(other) => value.push(other),
                        None => return Err("unterminated string".into()),
                    }
                }
                tokens.push(Token::Str(value));
            }
            _ => {
                let mut word = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_whitespace() || c == '(' || c == ')' || c == '"' {
                        break;
                    }
                    word.push(c);
                    chars.next();
                }
                tokens.push(Token::Word(word));
            }
        }
        if tokens.len() > 200 {
            return Err("filter is too long".into());
        }
    }
    Ok(tokens)
}

struct Parser {
    tokens: Vec<Token>,
    pos: usize,
    depth: usize,
}

impl Parser {
    fn peek_word(&self) -> Option<String> {
        match self.tokens.get(self.pos) {
            Some(Token::Word(w)) => Some(w.to_ascii_lowercase()),
            _ => None,
        }
    }

    fn expr(&mut self) -> Result<Filter, String> {
        let mut left = self.term()?;
        while self.peek_word().as_deref() == Some("or") {
            self.pos += 1;
            let right = self.term()?;
            left = Filter::Or(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn term(&mut self) -> Result<Filter, String> {
        let mut left = self.factor()?;
        while self.peek_word().as_deref() == Some("and") {
            self.pos += 1;
            let right = self.factor()?;
            left = Filter::And(Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn factor(&mut self) -> Result<Filter, String> {
        self.depth += 1;
        if self.depth > 20 {
            return Err("filter is nested too deeply".into());
        }
        let result = if self.peek_word().as_deref() == Some("not") {
            self.pos += 1;
            Ok(Filter::Not(Box::new(self.group()?)))
        } else if self.tokens.get(self.pos) == Some(&Token::Open) {
            self.group()
        } else {
            self.comparison()
        };
        self.depth -= 1;
        result
    }

    fn group(&mut self) -> Result<Filter, String> {
        if self.tokens.get(self.pos) != Some(&Token::Open) {
            return Err("expected (".into());
        }
        self.pos += 1;
        let inner = self.expr()?;
        if self.tokens.get(self.pos) != Some(&Token::Close) {
            return Err("expected )".into());
        }
        self.pos += 1;
        Ok(inner)
    }

    fn comparison(&mut self) -> Result<Filter, String> {
        let Some(Token::Word(attr)) = self.tokens.get(self.pos).cloned() else {
            return Err("expected an attribute".into());
        };
        self.pos += 1;
        let op = self.peek_word().ok_or("expected an operator")?;
        self.pos += 1;
        if op == "pr" {
            return Ok(Filter::Present(attr));
        }
        if !["eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"].contains(&op.as_str()) {
            return Err(format!("unsupported operator {op}"));
        }
        let value = match self.tokens.get(self.pos).cloned() {
            Some(Token::Str(s)) => Value::Str(s),
            Some(Token::Word(w)) => match w.to_ascii_lowercase().as_str() {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                "null" => Value::Null,
                other => Value::Number(other.parse().map_err(|_| format!("invalid value {w}"))?),
            },
            _ => return Err("expected a value".into()),
        };
        self.pos += 1;
        Ok(Filter::Compare { attr, op, value })
    }
}

/// Parses a filter expression.
pub fn parse(input: &str) -> Result<Filter, String> {
    if input.len() > 4096 {
        return Err("filter is too long".into());
    }
    let mut parser = Parser {
        tokens: tokenize(input)?,
        pos: 0,
        depth: 0,
    };
    let filter = parser.expr()?;
    if parser.pos != parser.tokens.len() {
        return Err("unexpected input after the filter".into());
    }
    Ok(filter)
}

/// An attribute's values on a resource, and whether comparisons are case
/// sensitive (`caseExact`).
pub struct Attribute {
    pub values: Vec<Value>,
    pub case_exact: bool,
}

/// Evaluates `filter` with `lookup` returning the attribute (lower-case
/// name without schema prefix) or `None` when the resource lacks it.
pub fn matches(filter: &Filter, lookup: &dyn Fn(&str) -> Option<Attribute>) -> bool {
    match filter {
        Filter::And(a, b) => matches(a, lookup) && matches(b, lookup),
        Filter::Or(a, b) => matches(a, lookup) || matches(b, lookup),
        Filter::Not(inner) => !matches(inner, lookup),
        Filter::Present(attr) => lookup(&normalize(attr)).is_some_and(|a| {
            a.values
                .iter()
                .any(|v| !matches!(v, Value::Null) && *v != Value::Str(String::new()))
        }),
        Filter::Compare { attr, op, value } => {
            let Some(attribute) = lookup(&normalize(attr)) else {
                return op == "ne";
            };
            let any = attribute
                .values
                .iter()
                .any(|v| compare(v, op, value, attribute.case_exact));
            if op == "ne" {
                attribute
                    .values
                    .iter()
                    .all(|v| compare(v, op, value, attribute.case_exact))
            } else {
                any
            }
        }
    }
}

/// `urn:…:User:userName` → `username`; `emails[type eq "work"].value` →
/// `emails.value`.
pub fn normalize(attr: &str) -> String {
    let without_schema = match attr.rfind(':') {
        Some(i) if attr.starts_with("urn:") => &attr[i + 1..],
        _ => attr,
    };
    let mut out = String::new();
    let mut depth = 0;
    for c in without_schema.chars() {
        match c {
            '[' => depth += 1,
            ']' => depth -= 1,
            c if depth == 0 => out.push(c.to_ascii_lowercase()),
            _ => {}
        }
    }
    if out == "emails" {
        "emails.value".into()
    } else {
        out
    }
}

fn compare(actual: &Value, op: &str, expected: &Value, case_exact: bool) -> bool {
    match (actual, expected) {
        (Value::Str(a), Value::Str(e)) => {
            let (a, e) = if case_exact {
                (a.clone(), e.clone())
            } else {
                (a.to_lowercase(), e.to_lowercase())
            };
            match op {
                "eq" => a == e,
                "ne" => a != e,
                "co" => a.contains(&e),
                "sw" => a.starts_with(&e),
                "ew" => a.ends_with(&e),
                "gt" => a > e,
                "ge" => a >= e,
                "lt" => a < e,
                "le" => a <= e,
                _ => false,
            }
        }
        (Value::Bool(a), Value::Bool(e)) => match op {
            "eq" => a == e,
            "ne" => a != e,
            _ => false,
        },
        // Some clients send booleans as strings.
        (Value::Bool(a), Value::Str(e)) => match op {
            "eq" => e.eq_ignore_ascii_case(&a.to_string()),
            "ne" => !e.eq_ignore_ascii_case(&a.to_string()),
            _ => false,
        },
        (_, Value::Null) => op == "ne",
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(attr: &str) -> Option<Attribute> {
        let (values, case_exact) = match attr {
            "username" => (vec![Value::Str("Ada@Acme.example".into())], false),
            "externalid" => (vec![Value::Str("00u1".into())], true),
            "emails.value" => (
                vec![
                    Value::Str("ada@acme.example".into()),
                    Value::Str("a@b.example".into()),
                ],
                false,
            ),
            "active" => (vec![Value::Bool(true)], false),
            _ => return None,
        };
        Some(Attribute { values, case_exact })
    }

    fn check(filter: &str) -> bool {
        matches(&parse(filter).unwrap(), &user)
    }

    #[test]
    fn evaluates_common_filters() {
        assert!(check(r#"userName eq "ada@acme.example""#));
        assert!(check(
            r#"urn:ietf:params:scim:schemas:core:2.0:User:userName eq "ADA@acme.example""#
        ));
        assert!(
            !check(r#"externalId eq "00U1""#),
            "externalId is case exact"
        );
        assert!(check(r#"externalId eq "00u1""#));
        assert!(check(r#"emails[type eq "work"].value eq "a@b.example""#));
        assert!(check(r#"emails co "acme""#));
        assert!(check(r#"userName sw "ada" and active eq true"#));
        assert!(check(
            r#"userName eq "x" or (externalId eq "00u1" and not (active eq false))"#
        ));
        assert!(check("externalId pr"));
        assert!(!check("title pr"));
        assert!(check(r#"title ne "x""#));
        assert!(check(r#"active eq "True""#));
        assert!(!check(r#"userName ne "ada@acme.example""#));
    }

    #[test]
    fn rejects_malformed_filters() {
        for bad in [
            "",
            "userName",
            r#"userName eq"#,
            r#"userName xx "a""#,
            r#"userName eq "a"#,
            r#"(userName eq "a""#,
            r#"userName eq "a" junk"#,
            &"(".repeat(50),
        ] {
            assert!(parse(bad).is_err(), "{bad}");
        }
    }
}
