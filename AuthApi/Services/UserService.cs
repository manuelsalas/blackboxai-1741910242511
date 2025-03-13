using AuthApi.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Services;

public class UserService : IUserService
{
    private readonly ITokenService _tokenService;
    private readonly ApplicationDbContext _context;
    private readonly ILogger<UserService> _logger;

    public UserService(
        ITokenService tokenService,
        ApplicationDbContext context,
        ILogger<UserService> logger)
    {
        _tokenService = tokenService;
        _context = context;
        _logger = logger;
    }

    public async Task<AuthResponse> RegisterAsync(RegisterRequest request)
    {
        try
        {
            if (await _context.Users.AnyAsync(u => u.Username == request.Username))
            {
                throw new InvalidOperationException("Username already exists");
            }

            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            {
                throw new InvalidOperationException("Email already exists");
            }

            var user = new User
            {
                Username = request.Username,
                Email = request.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.Password)
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"User {user.Username} registered successfully");

            var authResponse = _tokenService.CreateToken(user);
            user.RefreshToken = authResponse.RefreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
            await _context.SaveChangesAsync();

            return authResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during user registration");
            throw;
        }
    }

    public async Task<AuthResponse> LoginAsync(LoginRequest request)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);
        
        if (user == null || !BCrypt.Net.BCrypt.Verify(request.Password, user.PasswordHash))
        {
            throw new InvalidOperationException("Invalid username or password");
        }

        var authResponse = _tokenService.CreateToken(user);
        user.RefreshToken = authResponse.RefreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        await _context.SaveChangesAsync();

        return authResponse;
    }

    public async Task<AuthResponse> RefreshTokenAsync(string token, string refreshToken)
    {
        var userId = _tokenService.ValidateToken(token);
        if (userId == null)
        {
            throw new InvalidOperationException("Invalid token");
        }

        var user = await _context.Users.FirstOrDefaultAsync(u => 
            u.Id.ToString() == userId && 
            u.RefreshToken == refreshToken &&
            u.RefreshTokenExpiry > DateTime.UtcNow);

        if (user == null)
        {
            throw new InvalidOperationException("Invalid refresh token");
        }

        var authResponse = _tokenService.CreateToken(user);
        user.RefreshToken = authResponse.RefreshToken;
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        await _context.SaveChangesAsync();

        return authResponse;
    }

    public async Task<User?> GetUserByIdAsync(Guid id)
    {
        return await _context.Users.FindAsync(id);
    }

    public async Task<bool> ValidateUserCredentialsAsync(string username, string password)
    {
        var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);
        return user != null && BCrypt.Net.BCrypt.Verify(password, user.PasswordHash);
    }
}
