using System.Data.SqlClient;

namespace DemoApp.Data;

public class UsersRepository
{
    public string? GetDisplayName(string connectionString, int userId)
    {
        using var connection = new SqlConnection(connectionString);
        connection.Open();
        var cmd = new SqlCommand("SELECT DisplayName FROM Users WHERE Id = " + userId + " AND IsActive = 1", connection);
        return (string?)cmd.ExecuteScalar();
    }
}
