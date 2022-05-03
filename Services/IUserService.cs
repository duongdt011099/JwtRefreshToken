using test.Entities;
using test.Models;

namespace test.Services;

public interface IUserService
{
    AuthenticateResponse Authenticate(AuthenticateRequest model, string ipAddress);
    AuthenticateResponse RefreshToken(string token, string ipAddress);
    bool RevokeToken(string token, string ipAddress);
    IEnumerable<User> GetAll();
    User GetById(int id);
    void SeedData();
}