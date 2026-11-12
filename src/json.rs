//! ==============================================================================
//! Product:       Logihertz dm-verity Builder (lh-dmverity)
//! Module:        json.rs
//! Role:          Clean-Room Zero-Crate JSON Parser & Canonical Serializer
//! Organization:  Logihertz Systems (OPC) Private Limited
//! Developer:     Sameer Tawade (Creator, Founder, Director & Sole Developer)
//! Contact:       ops@logihertz.com / security@logihertz.com
//! License:       Apache-2.0
//! ==============================================================================

use std::fmt;

/// Representation of a JSON value in pure Rust without external crates
#[derive(Clone, Debug, PartialEq)]
pub enum JsonValue {
    /// JSON null
    Null,
    /// JSON boolean (true or false)
    Bool(bool),
    /// JSON number (stored as f64)
    Number(f64),
    /// JSON string
    String(String),
    /// JSON array of values
    Array(Vec<JsonValue>),
    /// JSON key-value object
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Look up a property inside an Object value
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        match self {
            JsonValue::Object(pairs) => {
                for (k, v) in pairs {
                    if k == key {
                        return Some(v);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Access value as string slice if it is a String variant
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Access value as bool if it is a Bool variant
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Access value as u64 if it is a Number variant
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            JsonValue::Number(n) => {
                if *n >= 0.0 && n.fract() == 0.0 {
                    Some(*n as u64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Access value as i64 if it is a Number variant
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Number(n) => {
                if n.fract() == 0.0 {
                    Some(*n as i64)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Access value as f64 if it is a Number variant
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            JsonValue::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Access value as array slice if it is an Array variant
    pub fn as_array(&self) -> Option<&Vec<JsonValue>> {
        match self {
            JsonValue::Array(a) => Some(a),
            _ => None,
        }
    }

    /// Access value as object key-value slice if it is an Object variant
    pub fn as_object(&self) -> Option<&Vec<(String, JsonValue)>> {
        match self {
            JsonValue::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Parse a JSON string into a JsonValue tree
    pub fn parse(input: &str) -> Result<Self, String> {
        let chars: Vec<char> = input.chars().collect();
        let mut idx = 0;
        skip_whitespace(&chars, &mut idx);
        let val = parse_value(&chars, &mut idx)?;
        skip_whitespace(&chars, &mut idx);
        if idx < chars.len() {
            return Err(format!(
                "Unexpected trailing characters at index {}: {:?}",
                idx,
                &chars[idx..std::cmp::min(idx + 10, chars.len())]
            ));
        }
        Ok(val)
    }

    /// Serialize value to canonical, compact JSON string
    pub fn to_json_string(&self) -> String {
        match self {
            JsonValue::Null => "null".to_string(),
            JsonValue::Bool(b) => {
                if *b {
                    "true".to_string()
                } else {
                    "false".to_string()
                }
            }
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && !n.is_infinite() && !n.is_nan() {
                    format!("{:.0}", n)
                } else {
                    format!("{}", n)
                }
            }
            JsonValue::String(s) => escape_string(s),
            JsonValue::Array(arr) => {
                let items: Vec<String> = arr.iter().map(|v| v.to_json_string()).collect();
                format!("[{}]", items.join(","))
            }
            JsonValue::Object(obj) => {
                let pairs: Vec<String> = obj
                    .iter()
                    .map(|(k, v)| format!("{}:{}", escape_string(k), v.to_json_string()))
                    .collect();
                format!("{{{}}}", pairs.join(","))
            }
        }
    }

    /// Serialize value to human-readable pretty JSON string with indentation
    pub fn to_pretty_string(&self) -> String {
        let mut out = String::new();
        self.format_pretty(&mut out, 0);
        out
    }

    fn format_pretty(&self, out: &mut String, indent: usize) {
        let indent_str = "  ".repeat(indent);
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && !n.is_infinite() && !n.is_nan() {
                    out.push_str(&format!("{:.0}", n));
                } else {
                    out.push_str(&format!("{}", n));
                }
            }
            JsonValue::String(s) => out.push_str(&escape_string(s)),
            JsonValue::Array(arr) => {
                if arr.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                let child_indent = "  ".repeat(indent + 1);
                for (i, item) in arr.iter().enumerate() {
                    out.push_str(&child_indent);
                    item.format_pretty(out, indent + 1);
                    if i + 1 < arr.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&indent_str);
                out.push(']');
            }
            JsonValue::Object(obj) => {
                if obj.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                let child_indent = "  ".repeat(indent + 1);
                for (i, (k, v)) in obj.iter().enumerate() {
                    out.push_str(&child_indent);
                    out.push_str(&escape_string(k));
                    out.push_str(": ");
                    v.format_pretty(out, indent + 1);
                    if i + 1 < obj.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&indent_str);
                out.push('}');
            }
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_json_string())
    }
}

fn skip_whitespace(chars: &[char], idx: &mut usize) {
    while *idx < chars.len() && chars[*idx].is_whitespace() {
        *idx += 1;
    }
}

fn parse_value(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    skip_whitespace(chars, idx);
    if *idx >= chars.len() {
        return Err("Unexpected end of input while expecting JSON value".to_string());
    }

    match chars[*idx] {
        'n' => parse_null(chars, idx),
        't' | 'f' => parse_bool(chars, idx),
        '"' => parse_string(chars, idx).map(JsonValue::String),
        '[' => parse_array(chars, idx),
        '{' => parse_object(chars, idx),
        '-' | '0'..='9' => parse_number(chars, idx),
        c => Err(format!("Unexpected character '{}' at index {}", c, *idx)),
    }
}

fn parse_null(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx + 4 <= chars.len() && chars[*idx..*idx + 4] == ['n', 'u', 'l', 'l'] {
        *idx += 4;
        Ok(JsonValue::Null)
    } else {
        Err(format!("Invalid null literal at index {}", *idx))
    }
}

fn parse_bool(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx + 4 <= chars.len() && chars[*idx..*idx + 4] == ['t', 'r', 'u', 'e'] {
        *idx += 4;
        Ok(JsonValue::Bool(true))
    } else if *idx + 5 <= chars.len() && chars[*idx..*idx + 5] == ['f', 'a', 'l', 's', 'e'] {
        *idx += 5;
        Ok(JsonValue::Bool(false))
    } else {
        Err(format!("Invalid boolean literal at index {}", *idx))
    }
}

fn parse_string(chars: &[char], idx: &mut usize) -> Result<String, String> {
    if *idx >= chars.len() || chars[*idx] != '"' {
        return Err(format!("Expected '\"' at index {}", *idx));
    }
    *idx += 1;
    let mut s = String::new();

    while *idx < chars.len() {
        let c = chars[*idx];
        *idx += 1;
        match c {
            '"' => return Ok(s),
            '\\' => {
                if *idx >= chars.len() {
                    return Err("Unterminated escape sequence at end of input".to_string());
                }
                let esc = chars[*idx];
                *idx += 1;
                match esc {
                    '"' => s.push('"'),
                    '\\' => s.push('\\'),
                    '/' => s.push('/'),
                    'b' => s.push('\x08'),
                    'f' => s.push('\x0c'),
                    'n' => s.push('\n'),
                    'r' => s.push('\r'),
                    't' => s.push('\t'),
                    'u' => {
                        if *idx + 4 > chars.len() {
                            return Err("Incomplete \\u hex escape".to_string());
                        }
                        let hex_str: String = chars[*idx..*idx + 4].iter().collect();
                        *idx += 4;
                        let codepoint = u32::from_str_radix(&hex_str, 16)
                            .map_err(|e| format!("Invalid \\u hex escape: {}", e))?;
                        if let Some(unicode_char) = char::from_u32(codepoint) {
                            s.push(unicode_char);
                        } else {
                            s.push('\u{FFFD}');
                        }
                    }
                    other => return Err(format!("Invalid escape sequence '\\{}'", other)),
                }
            }
            other => s.push(other),
        }
    }

    Err("Unterminated string literal at end of input".to_string())
}

fn parse_number(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    let start = *idx;
    if *idx < chars.len() && chars[*idx] == '-' {
        *idx += 1;
    }

    while *idx < chars.len() && chars[*idx].is_ascii_digit() {
        *idx += 1;
    }

    if *idx < chars.len() && chars[*idx] == '.' {
        *idx += 1;
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }

    if *idx < chars.len() && (chars[*idx] == 'e' || chars[*idx] == 'E') {
        *idx += 1;
        if *idx < chars.len() && (chars[*idx] == '+' || chars[*idx] == '-') {
            *idx += 1;
        }
        while *idx < chars.len() && chars[*idx].is_ascii_digit() {
            *idx += 1;
        }
    }

    let num_str: String = chars[start..*idx].iter().collect();
    let num: f64 = num_str
        .parse()
        .map_err(|e| format!("Invalid number '{}': {}", num_str, e))?;

    Ok(JsonValue::Number(num))
}

fn parse_array(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx >= chars.len() || chars[*idx] != '[' {
        return Err(format!("Expected '[' at index {}", *idx));
    }
    *idx += 1;
    let mut items = Vec::new();

    skip_whitespace(chars, idx);
    if *idx < chars.len() && chars[*idx] == ']' {
        *idx += 1;
        return Ok(JsonValue::Array(items));
    }

    loop {
        skip_whitespace(chars, idx);
        let val = parse_value(chars, idx)?;
        items.push(val);

        skip_whitespace(chars, idx);
        if *idx >= chars.len() {
            return Err("Unterminated array at end of input".to_string());
        }

        match chars[*idx] {
            ',' => *idx += 1,
            ']' => {
                *idx += 1;
                break;
            }
            c => return Err(format!("Expected ',' or ']' in array, got '{}'", c)),
        }
    }

    Ok(JsonValue::Array(items))
}

fn parse_object(chars: &[char], idx: &mut usize) -> Result<JsonValue, String> {
    if *idx >= chars.len() || chars[*idx] != '{' {
        return Err(format!("Expected '{{' at index {}", *idx));
    }
    *idx += 1;
    let mut pairs = Vec::new();

    skip_whitespace(chars, idx);
    if *idx < chars.len() && chars[*idx] == '}' {
        *idx += 1;
        return Ok(JsonValue::Object(pairs));
    }

    loop {
        skip_whitespace(chars, idx);
        if *idx >= chars.len() || chars[*idx] != '"' {
            return Err(format!("Expected string key in object at index {}", *idx));
        }
        let key = parse_string(chars, idx)?;

        skip_whitespace(chars, idx);
        if *idx >= chars.len() || chars[*idx] != ':' {
            return Err(format!(
                "Expected ':' after key '{}' at index {}",
                key, *idx
            ));
        }
        *idx += 1;

        skip_whitespace(chars, idx);
        let val = parse_value(chars, idx)?;
        pairs.push((key, val));

        skip_whitespace(chars, idx);
        if *idx >= chars.len() {
            return Err("Unterminated object at end of input".to_string());
        }

        match chars[*idx] {
            ',' => *idx += 1,
            '}' => {
                *idx += 1;
                break;
            }
            c => return Err(format!("Expected ',' or '}}' in object, got '{}'", c)),
        }
    }

    Ok(JsonValue::Object(pairs))
}

fn escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_primitives() {
        assert_eq!(JsonValue::parse("null").unwrap(), JsonValue::Null);
        assert_eq!(JsonValue::parse("true").unwrap(), JsonValue::Bool(true));
        assert_eq!(JsonValue::parse("false").unwrap(), JsonValue::Bool(false));
        assert_eq!(JsonValue::parse("42").unwrap(), JsonValue::Number(42.0));
        assert_eq!(JsonValue::parse("-17.5").unwrap(), JsonValue::Number(-17.5));
        assert_eq!(
            JsonValue::parse("\"hello\\nworld\"").unwrap(),
            JsonValue::String("hello\nworld".to_string())
        );
    }

    #[test]
    fn test_json_nested() {
        let raw = r#"{
            "tool": "lh-dmverity",
            "active": true,
            "blocks": 16,
            "algorithms": ["sha256", "sha512"],
            "nested": {
                "verified": false,
                "notes": null
            }
        }"#;

        let parsed = JsonValue::parse(raw).expect("JSON parse failed");
        assert_eq!(
            parsed.get("tool").and_then(|v| v.as_str()),
            Some("lh-dmverity")
        );
        assert_eq!(parsed.get("active").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(parsed.get("blocks").and_then(|v| v.as_u64()), Some(16));

        let arr = parsed.get("algorithms").and_then(|v| v.as_array()).unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_str(), Some("sha256"));

        let nested = parsed.get("nested").unwrap();
        assert_eq!(
            nested.get("verified").and_then(|v| v.as_bool()),
            Some(false)
        );
        assert_eq!(nested.get("notes"), Some(&JsonValue::Null));
    }
}
