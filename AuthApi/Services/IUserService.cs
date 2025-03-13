using AuthApi.Models;

namespace AuthApi.Services;

public interface IUserService
{
    Task<AuthResponse> RegisterAsync(RegisterRequest request);
    Task<AuthResponse> LoginAsync(LoginRequest request);
    Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken);
    Task<User?> GetUserByIdAsync(Guid id);
    Task<bool> ValidateUserCredentialsAsync(string username, string password);
}
