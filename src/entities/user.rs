use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: String,
    pub email: String,
    pub password_hash: String,
    pub display_name: Option<String>,
    pub roles: String,
    pub is_confirmed: bool,
    pub totp_secret: Option<String>,
    pub created_at: String,
    pub last_login_at: Option<String>,
}

impl User {
    pub fn is_admin(&self) -> bool {
        self.roles().contains(&"admin")
    }

    pub fn roles(&self) -> Vec<&str> {
        self.roles
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect()
    }

    pub fn has_role(&self, role: &str) -> bool {
        self.roles().contains(&role)
    }

    pub fn has_totp(&self) -> bool {
        self.totp_secret.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_user(roles: &str) -> User {
        User {
            id: "id".into(),
            email: "a@b.com".into(),
            password_hash: "hash".into(),
            display_name: None,
            roles: roles.into(),
            is_confirmed: true,
            totp_secret: None,
            created_at: "2024-01-01".into(),
            last_login_at: None,
        }
    }

    #[test]
    fn is_admin_with_admin_role() {
        assert!(make_user("admin").is_admin());
        assert!(make_user("member,admin").is_admin());
    }

    #[test]
    fn is_admin_without_admin_role() {
        assert!(!make_user("member").is_admin());
        assert!(!make_user("").is_admin());
    }

    #[test]
    fn roles_parses_csv() {
        assert_eq!(make_user("a,b,c").roles(), vec!["a", "b", "c"]);
        assert_eq!(make_user(" a , b ").roles(), vec!["a", "b"]);
    }

    #[test]
    fn empty_roles() {
        assert!(make_user("").roles().is_empty());
    }

    #[test]
    fn has_role_finds_role() {
        let u = make_user("member,admin");
        assert!(u.has_role("member"));
        assert!(u.has_role("admin"));
        assert!(!u.has_role("editor"));
    }
}
