//! Port of `zip_set_default_password.c`.

use crate::zip::open::Archive;
use crate::zip::zipint::Password;

impl<R> Archive<R> {
    /// Sets the password that encrypted entries are read, and encrypted
    /// ones written, with when none is given, or removes it with `None` or
    /// an empty password: port of `zip_set_default_password`. The password
    /// is taken up to its first NUL byte, as libzip takes a C string.
    ///
    /// Differs from libzip, which cannot fail here but for memory: it
    /// returns nothing.
    pub fn set_default_password(&mut self, passwd: Option<&[u8]>) {
        self.default_password = passwd.map(Password::new).filter(|p| !p.is_empty());
    }
}
