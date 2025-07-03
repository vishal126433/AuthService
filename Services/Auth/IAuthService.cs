using AuthService.DTOs;

namespace AuthService.Services.Auth
{
    public interface IAuthService
    {
        /// <summary>
        /// register new user
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        Task<string> RegisterAsync(RegisterRequest req);
        /// <summary>
        /// change password of an existing user
        /// </summary>
        /// <param name="request"></param>
        /// <returns></returns>
        Task<string> ChangePasswordAsync(ChangePasswordRequest request);
        /// <summary>
        /// login of the existing user
        /// </summary>
        /// <param name="req"></param>
        /// <returns></returns>
        TokenResponse? Login(LoginRequest req);
        /// <summary>
        /// code to generate new access token
        /// </summary>
        /// <param name="refreshToken"></param>
        /// <returns></returns>
        TokenResponse? RefreshToken(string refreshToken);
    }
}
