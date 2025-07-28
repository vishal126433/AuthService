
using AuthService.Models;

namespace AuthService.Helpers
{
    public class ApiResponse<T>
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string? Message { get; set; }
        public List<string>? Errors { get; set; }
        public T? Data { get; set; }

        public static ApiResponse<T> SuccessResponse(T data, int statusCode = 200, string? message = null)
        {
            return new ApiResponse<T>
            {
                Success = true,
                StatusCode = statusCode,
                Message = message,
                Data = data
            };
        }

        public static ApiResponse<T> ErrorResponse(List<string> errors, int statusCode = 400, string? message = null)
        {
            return new ApiResponse<T>
            {
                Success = false,
                StatusCode = statusCode,
                Message = message,
                Errors = errors
            };
        }

        public static ApiResponse<T> SingleError(string error, int statusCode = 400, string? message = null)
        {
            return ErrorResponse(new List<string> { error }, statusCode, message);
        }


    }
}
