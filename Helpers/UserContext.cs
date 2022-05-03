using Microsoft.EntityFrameworkCore;
using test.Entities;

namespace test.Helpers;

public class UserContext : DbContext
{
    public UserContext(DbContextOptions dbContextOptions)
        : base(dbContextOptions)
    {
    }

    public DbSet<User> Users { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<User>().HasData(new User
        {
            Id = 1,
            FirstName = "John",
            LastName = "Doe",
            Username = "johndoe",
            Password = "def@123"
        });
    }
}