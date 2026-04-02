admin-panel = Admin Panel

setup-title = Initial Setup
setup-subtitle = Create the first administrator account to get started.
setup-email-label = Admin Email
setup-email-placeholder = admin@email.com
setup-name-label = Display Name
setup-name-placeholder = Your name
setup-password-label = Password
setup-password-placeholder = Set a secure password
setup-submit = Create Admin Account
setup-token-label = Setup Token
setup-token-placeholder = Token from the server console
setup-error-invalid-token = Invalid setup token
setup-error-email-exists = This email address is already in use
setup-error-already-configured = Setup has already been completed

login-title = Sign In
login-subtitle = Enter your credentials to access your account.
login-email-label = Email
login-email-placeholder = name@email.com
login-password-label = Password
login-password-placeholder = Your password
login-submit = Sign In
login-error-invalid = Email or password is invalid.
login-error-rate-limited = Too many login attempts. Please try again later.
login-error-account-locked = Account locked. Please try again later.
login-error-session-expired = Session expired, please sign in again

authorize-title = Authorize Application
authorize-description-prefix = requests access to your account
authorize-scope-label = Requested scope:
authorize-allow = Allow
authorize-deny = Deny

error-title = Error
error-back-home = Back to home

sidebar-dashboard = Dashboard
sidebar-users = Users
sidebar-email-templates = Email Templates
sidebar-clients = Clients
sidebar-create-client = Create Client
sidebar-create-user = Create User
sidebar-logout = Sign Out

email-templates-title = Email Templates
email-template-edit-title = Edit Email Template
email-template-type-confirm-registration = Confirm Registration
email-template-type-change-email = Change Email Address
email-template-type-reset-password = Reset Password
email-template-subject = Subject
email-template-body = Content
email-template-variables = Available Variables
email-template-updated = Last Updated
email-template-save = Save

dashboard-title = Dashboard
dashboard-total-users = Total Users
dashboard-active-users = Active Sessions
dashboard-locked-users = Locked Accounts
dashboard-quick-actions = Quick Actions
dashboard-manage-users = Manage Users
dashboard-manage-clients = Manage Clients
dashboard-manage-email-templates = Manage Email Templates
dashboard-manage-legal-pages = Manage Legal Pages

users-title = Users
users-col-name = Name
users-col-email = Email
users-col-access-level = Roles
users-col-last-login = Last Login
users-col-date-added = Created
users-badge-admin = Admin
users-badge-user = User
users-delete-confirm = Really delete this user?
users-locked-tooltip = Locked until
users-create-tooltip = Create user

user-create-title = Create User
user-create-email-label = Email
user-create-email-placeholder = user@example.com
user-create-name-label = Display Name
user-create-name-placeholder = Name
user-create-password-label = Password
user-create-password-placeholder = Set password
user-create-generate-password = Generate Password
user-create-copy-password = Copy to clipboard
user-create-copied = Password copied to clipboard
user-create-roles-label = Roles
user-create-submit = Create User
user-create-cancel = Cancel
user-create-error-email-exists = This email address is already in use

user-edit-title = Edit User
user-edit-email-label = Email
user-edit-name-label = Display Name
user-edit-name-placeholder = Name
user-edit-password-label = New Password
user-edit-password-placeholder = Leave empty to keep current password
user-edit-submit = Save
user-edit-locked-notice = Locked until
user-edit-unlock-label = Unlock account

profile-title = My Profile
profile-email-label = Email
profile-roles-label = Roles
profile-last-login-label = Last Login
profile-name-label = Display Name
profile-name-placeholder = Name
profile-submit = Save
profile-saved = Changes saved

profile-password-title = Change Password
profile-password-current-label = Current Password
profile-password-current-placeholder = Your current password
profile-password-new-label = New Password
profile-password-new-placeholder = New password
profile-password-confirm-label = Confirm New Password
profile-password-confirm-placeholder = Repeat new password
profile-password-submit = Change Password
profile-password-cancel = Cancel
profile-password-saved = Password changed successfully
profile-password-error-wrong = Current password is incorrect
profile-password-error-mismatch = New passwords do not match

clients-title = Clients
clients-col-id = Client ID
clients-col-redirect-uri = Redirect URI
clients-col-post-logout-uri = Post-Logout URI
clients-col-date-added = Created
clients-delete-confirm = Really delete this client?

client-create-title = Create Client
client-create-id-label = Client ID
client-create-id-placeholder = e.g. my-app
client-create-secret-label = Client Secret
client-create-secret-placeholder = Set a secure secret
client-create-redirect-uri-label = Redirect URI
client-create-redirect-uri-placeholder = http://localhost/signin-oidc
client-create-post-logout-uri-label = Post-Logout Redirect URI
client-create-post-logout-uri-placeholder = http://localhost/signout-callback-oidc
client-create-generate-secret = Generate Secret
client-create-copy-secret = Copy to clipboard
client-create-copied = Secret copied to clipboard
client-create-submit = Create Client
client-create-cancel = Cancel
client-create-error-id-exists = This Client ID is already in use

client-edit-title = Edit Client
client-edit-id-label = Client ID
client-edit-secret-label = New Client Secret
client-edit-secret-placeholder = Leave empty to keep current secret
client-edit-redirect-uri-label = Redirect URI
client-edit-post-logout-uri-label = Post-Logout Redirect URI
client-edit-submit = Save
client-edit-cancel = Cancel

password-error-too-short = Password must be at least 10 characters long
password-error-no-uppercase = Password must contain at least one uppercase letter
password-error-no-lowercase = Password must contain at least one lowercase letter
password-error-too-few-digits = Password must contain at least one digit
password-error-too-few-special = Password must contain at least one special character
password-error-too-weak = Password is too weak or too commonly used

secret-error-too-short = Client Secret must be at least 16 characters long
secret-error-no-uppercase = Client Secret must contain at least one uppercase letter
secret-error-no-lowercase = Client Secret must contain at least one lowercase letter
secret-error-too-few-digits = Client Secret must contain at least two digits
secret-error-too-few-special = Client Secret must contain at least two special characters
secret-error-too-weak = Client Secret is too weak or too commonly used

legal-imprint-title = Imprint
legal-privacy-title = Privacy Policy
legal-back = Back to sign in

sidebar-legal-pages = Legal
legal-pages-title = Legal Pages
legal-page-edit-title = Edit Page
legal-pages-col-type = Page
legal-pages-col-status = Status
legal-pages-status-active = Active
legal-pages-status-empty = Empty

csrf-token-invalid = Invalid CSRF token
confirm-delete = Really delete?
copied = Copied

language-label = Language
language-de = German
language-en = English

email-default-confirm-registration-subject = Confirm registration
email-default-confirm-registration-body =
    <p>Hello {"{{name}}"},</p>
    <p>Please confirm your email address by clicking the following link:</p>
    <p><a href="{"{{link}}"}">Confirm registration</a></p>
    <p>Best regards,</p>
    <p>GT Id Team</p>

email-default-change-email-subject = Change email address
email-default-change-email-body =
    <p>Hello {"{{name}}"},</p>
    <p>You have requested to change your email address. Please confirm the new address by clicking the following link:</p>
    <p><a href="{"{{link}}"}">Confirm email address</a></p>
    <p>Best regards,</p>
    <p>GT Id Team</p>

email-default-reset-password-subject = Reset password
email-default-reset-password-body =
    <p>Hello {"{{name}}"},</p>
    <p>You have requested to reset your password. Click the following link to set a new password:</p>
    <p><a href="{"{{link}}"}">Reset password</a></p>
    <p>Best regards,</p>
    <p>GT Id Team</p>
