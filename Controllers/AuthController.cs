//using Microsoft.AspNetCore.Mvc;
//using Microsoft.AspNetCore.Identity;
//using AuthService.DTOs;
//using AuthService.Services;
//using AuthService.Interfaces;
//using AuthService.Helpers;

//namespace AuthService.Controllers
//{
//    [ApiController]
//    [Route("[controller]")]
//    public class AuthController : ControllerBase
//    {
//        private readonly IAuthService _authService;

//        public AuthController(IAuthService authService)
//        {
//            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
//        }

//        [HttpPost("register")]
//        public async Task<IActionResult> Register([FromBody] RegisterRequest req)
//        {
//            try
//            {
//                var result = await _authService.RegisterAsync(req);
//                return Ok(ApiResponse<string>.SuccessResponse(result, 200, ResponseMessages.Auth.Registered));
//            }
//            catch (Exception ex)
//            {
//                return BadRequest(ApiResponse<string>.SingleError(ex.Message));
//            }
//        }

//        [HttpPut("change-password")]
//        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
//        {
//            try
//            {
//                var result = await _authService.ChangePasswordAsync(req);
//                return Ok(ApiResponse<string>.SuccessResponse(result, 200, ResponseMessages.Auth.PasswordChanged));
//            }
//            catch (Exception ex)
//            {
//                return BadRequest(ApiResponse<string>.SingleError(ex.Message));
//            }
//        }

//        [HttpPost("login")]
//        public IActionResult Login([FromBody] LoginRequest req)
//        {
//            if (req == null || string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
//            {
//                return BadRequest(ApiResponse<string>.SingleError(
//                    ResponseMessages.Auth.EmailPasswordRequired));
//            }

//            try
//            {
//                var tokenResponse = _authService.Login(req);
//                CookieHelper.AppendRefreshToken(Response, tokenResponse.RefreshToken!);

//                return Ok(ApiResponse<object>.SuccessResponse(new
//                {
//                    accessToken = tokenResponse.AccessToken
//                }, 200, ResponseMessages.Auth.LoggedIn));
//            }
//            catch (UnauthorizedAccessException ex)
//            {
//                return Unauthorized(ApiResponse<string>.SingleError(ex.Message));
//            }
//            catch (Exception)
//            {
//                return StatusCode(500, ApiResponse<string>.SingleError(ResponseMessages.Common.ServerError));
//            }
//        }

//        [HttpPost("refresh-token")]
//        public IActionResult RefreshToken()
//        {
//            var refreshToken = Request.Cookies["refreshToken"];
//            var newToken = _authService.RefreshToken(refreshToken ?? "");
//            if (newToken == null)
//                return Unauthorized("Invalid or expired refresh token");

//            return Ok(new TokenResponse { AccessToken = newToken.AccessToken });
//        }

//        [HttpPost("logout")]
//        public IActionResult Logout()
//        {
//            CookieHelper.DeleteRefreshToken(Response);
//            return Ok(ApiResponse<string>.SuccessResponse(null, 200, ResponseMessages.Auth.LoggedOut));
//        }
//    }
//}


using Microsoft.AspNetCore.Mvc;
using AuthService.DTOs;
using AuthService.Services;
using AuthService.Interfaces;
using AuthService.Helpers;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService ?? throw new ArgumentNullException(nameof(authService));
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest req)
        {
            var result = await _authService.RegisterAsync(req);
            return Ok(ApiResponse<string>.SuccessResponse(result, 200, ResponseMessages.Auth.Registered));
        }

        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest req)
        {
            var result = await _authService.ChangePasswordAsync(req);
            return Ok(ApiResponse<string>.SuccessResponse(result, 200, ResponseMessages.Auth.PasswordChanged));
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest req)
        {
            if (req == null || string.IsNullOrWhiteSpace(req.Email) || string.IsNullOrWhiteSpace(req.Password))
            {
                return BadRequest(ApiResponse<string>.SingleError(
                    ResponseMessages.Auth.EmailPasswordRequired));
            }

            var tokenResponse = _authService.Login(req);
            CookieHelper.AppendRefreshToken(Response, tokenResponse.RefreshToken!);

            return Ok(ApiResponse<object>.SuccessResponse(new
            {
                accessToken = tokenResponse.AccessToken
            }, 200, ResponseMessages.Auth.LoggedIn));
        }

        [HttpPost("refresh-token")]
        public IActionResult RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            var newToken = _authService.RefreshToken(refreshToken ?? "");
            if (newToken == null)
                return Unauthorized("Invalid or expired refresh token");

            return Ok(new TokenResponse { AccessToken = newToken.AccessToken });
        }

        [HttpPost("logout")]
        public IActionResult Logout()
        {
            CookieHelper.DeleteRefreshToken(Response);
            return Ok(ApiResponse<string>.SuccessResponse(null, 200, ResponseMessages.Auth.LoggedOut));
        }
    }
}
