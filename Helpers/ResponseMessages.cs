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
        }

        public static class Common
        {
            public const string ServerError = "An unexpected error occurred.";
        }
    }
}
