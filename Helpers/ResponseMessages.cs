namespace AuthService.Helpers
{
    public static class ResponseMessages
    {
        public static class Auth
        {
            public const string Registered = "User registered successfully.";
            public const string PasswordChanged = "Password changed successfully.";
            public const string LoggedIn = "User logged in successfully.";
            public const string LoggedOut = "User logged out successfully.";
            public const string InvalidRefreshToken = "Invalid or expired refresh token.";
            public const string TokenRefreshed = "Token refreshed successfully.";
            public const string EmailPasswordRequired = "Email and password are required.";
            public const string DBContextNull = "DbContext cannot be null.";
            public const string UserNameEmailExist = "Username or Email already exists";
            public const string Required = "Username, old password, and new password are required.";
            public const string NoUser = "User not found";
            public const string PasswordIncorrect = "Old password is incorrect";
            public const string NoNewAndOld = "New password cannot be the same as the old password";
            public const string InvalidEmailPassword = "Invalid email or password.";
            public const string UserInactive = "This user is inactive. Please contact the administrator.";
            public const string ConfigurationNull = "Configuration cannot be null.";
            public const string LoggerNull = "Logger cannot be null.";






        }

        public static class Common
        {
            public const string ServerError = "An unexpected error occurred.";
        }
    }
}
