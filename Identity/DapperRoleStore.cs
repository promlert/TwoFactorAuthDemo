using Microsoft.AspNetCore.Identity;
using System;
using System.Threading;
using System.Threading.Tasks;
using Dapper;
using Microsoft.Data.SqlClient;

namespace TwoFactorAuthDemo.Identity
{
    public class DapperRoleStore : IRoleStore<IdentityRole>
    {
        private readonly string _connectionString;

        public DapperRoleStore(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection");
        }

        public async Task<IdentityResult> CreateAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var rows = await connection.ExecuteAsync(
                    @"INSERT INTO AspNetRoles (Id, Name, NormalizedName, ConcurrencyStamp)
                        VALUES (@Id, @Name, @NormalizedName, @ConcurrencyStamp)",
                    new
                    {
                        role.Id,
                        role.Name,
                        role.NormalizedName,
                        role.ConcurrencyStamp
                    });

                return rows > 0 ? IdentityResult.Success : IdentityResult.Failed(new IdentityError { Description = "Failed to create role." });
            }
        }

        public async Task<IdentityResult> UpdateAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var rows = await connection.ExecuteAsync(
                    @"UPDATE AspNetRoles
                        SET Name = @Name, NormalizedName = @NormalizedName, ConcurrencyStamp = @ConcurrencyStamp
                        WHERE Id = @Id",
                    new
                    {
                        role.Id,
                        role.Name,
                        role.NormalizedName,
                        role.ConcurrencyStamp
                    });

                return rows > 0 ? IdentityResult.Success : IdentityResult.Failed(new IdentityError { Description = "Failed to update role." });
            }
        }

        public async Task<IdentityResult> DeleteAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                var rows = await connection.ExecuteAsync(
                    "DELETE FROM AspNetRoles WHERE Id = @Id",
                    new { role.Id });

                return rows > 0 ? IdentityResult.Success : IdentityResult.Failed(new IdentityError { Description = "Failed to delete role." });
            }
        }

        public async Task<IdentityRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                return await connection.QuerySingleOrDefaultAsync<IdentityRole>(
                    "SELECT * FROM AspNetRoles WHERE Id = @Id",
                    new { Id = roleId });
            }
        }

        public async Task<IdentityRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                return await connection.QuerySingleOrDefaultAsync<IdentityRole>(
                    "SELECT * FROM AspNetRoles WHERE NormalizedName = @NormalizedName",
                    new { NormalizedName = normalizedRoleName });
            }
        }

        public Task<string> GetRoleIdAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.Id);
        }

        public Task<string> GetRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.Name);
        }

        public Task<string> GetNormalizedRoleNameAsync(IdentityRole role, CancellationToken cancellationToken)
        {
            return Task.FromResult(role.NormalizedName);
        }

        public Task SetRoleNameAsync(IdentityRole role, string roleName, CancellationToken cancellationToken)
        {
            role.Name = roleName;
            return Task.CompletedTask;
        }

        public Task SetNormalizedRoleNameAsync(IdentityRole role, string normalizedName, CancellationToken cancellationToken)
        {
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        public void Dispose() { }
    }
}