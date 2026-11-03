//! User roles. The stored values are the `users.role` column values in `specs/database.md`.

/// `admin` or `user`. Stored as lowercase text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    User,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::User => "user",
        }
    }

    /// Parses a stored role. Returns `None` for any value outside the vocabulary,
    /// so the caller can fail closed.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "admin" => Some(Role::Admin),
            "user" => Some(Role::User),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_only_the_two_roles() {
        assert_eq!(Role::parse("admin"), Some(Role::Admin));
        assert_eq!(Role::parse("user"), Some(Role::User));
        assert_eq!(Role::parse("Admin"), None);
        assert_eq!(Role::parse(""), None);
    }
}
