using Microsoft.EntityFrameworkCore;
using AuthService.Models;
using System.Collections.Generic;
using System.Data;

namespace AuthService.Data
{
    public class AuthDbContext : DbContext
    {
        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options) { }

        // Define your DbSets here
        public DbSet<User> Users { get; set; }
        public DbSet<Role> Roles { get; set; }
        //public DbSet<TaskItem> Tasks { get; set; }

    }
}
