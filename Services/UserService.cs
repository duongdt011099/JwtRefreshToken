using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using test.Entities;
using test.Helpers;
using test.Models;

namespace test.Services;

public class UserService : IUserService
{
    private UserContext _context;
    private readonly AppSettings _appSettings;

    public UserService(
        UserContext context,
        IOptions<AppSettings> appSettings)
    {
        _context = context;
        _appSettings = appSettings.Value;
    }

    public AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress)
    {
        var user = _context.Users.SingleOrDefault(x => x.Username == model.Username && x.Password == model.Password);

        // return null if user not found
        if (user == null) return null;

        // authentication successful so generate jwt and refresh tokens
        var jwtToken = generateJwtToken(user);
        var refreshToken = generateRefreshToken(ipAddress);

        // save refresh token
        user.RefreshTokens.Add(refreshToken);
        _context.Update(user);
        _context.SaveChanges();

        return new AuthenticateResponse(user, jwtToken, refreshToken.Token);
    }

    public IEnumerable<User> GetAll()
    {
        return _context.Users;
    }

    public User GetById(int id)
    {
        return _context.Users.Find(id);
    }

    public AuthenticateResponse RefreshToken(string token, string ipAddress)
    {
        var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

        // return null if no user found with token
        if (user == null) return null;

        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

        // return null if token is no longer active
        if (!refreshToken.IsActive) return null;

        // replace old refresh token with a new one and save
        var newRefreshToken = generateRefreshToken(ipAddress);
        refreshToken.Revoked = DateTime.UtcNow;
        refreshToken.RevokedByIp = ipAddress;
        refreshToken.ReplacedByToken = newRefreshToken.Token;
        user.RefreshTokens.Add(newRefreshToken);
        _context.Update(user);
        _context.SaveChanges();

        // generate new jwt
        var jwtToken = generateJwtToken(user);

        return new AuthenticateResponse(user, jwtToken, newRefreshToken.Token);
    }

    public bool RevokeToken(string token, string ipAddress)
    {
        var user = _context.Users.SingleOrDefault(u => u.RefreshTokens.Any(t => t.Token == token));

        // return false if no user found with token
        if (user == null) return false;

        var refreshToken = user.RefreshTokens.Single(x => x.Token == token);

        // return false if token is not active
        if (!refreshToken.IsActive) return false;

        // revoke token and save
        refreshToken.Revoked = DateTime.UtcNow;
        refreshToken.RevokedByIp = ipAddress;
        _context.Update(user);
        _context.SaveChanges();

        return true;
    }

    private string generateJwtToken(User user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]
            {
                    new Claim(ClaimTypes.Name, user.Id.ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private RefreshToken generateRefreshToken(string ipAddress)
    {
        using (var rng = RandomNumberGenerator.Create())
        {
            var randomBytes = new byte[64];
            rng.GetBytes(randomBytes);
            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                Expires = DateTime.UtcNow.AddDays(7),
                Created = DateTime.UtcNow,
                CreatedByIp = ipAddress
            };
        }
    }

    public void SeedData()
    {
        _context.Database.EnsureCreated();
    }
}