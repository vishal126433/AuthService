using Microsoft.AspNetCore.Http;
using System;

namespace AuthService.Helpers
{
    public static class CookieHelper
    {
        public static void AppendRefreshToken(HttpResponse response, string refreshToken)
        {
            response.Cookies.Append("refreshToken", refreshToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Expires = DateTime.UtcNow.AddMinutes(30),
                Path = "/"
            });




        }

        public static void DeleteRefreshToken(HttpResponse response)
        {
            response.Cookies.Delete("refreshToken", new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                Path = "/"
            });
        }
    }
}
