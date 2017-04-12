using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.SqlClient;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Helpers
{
    internal static class AdoDataHelper
    {
        public static List<Dictionary<string, object>> GetRecords(string commandText, params SqlParameter[] parameters)
        {
            using (var conn = GetConnection())
            using (var command = conn.CreateCommand())
            {
                command.CommandText = commandText;
                foreach (var parameter in parameters)
                {
                    command.Parameters.Add(parameter);
                }
                return command.ExecuteReader().ToList();
            }
        }
        private static string GetConnectionString()
        {
            var connectionString = ConfigurationManager.ConnectionStrings["OsapConnectionString"];
            if (connectionString == null)
                throw new ConfigurationErrorsException("Connection string 'OsapConnectionString' not found.");
            return connectionString.ConnectionString;
        }

        private static IDbConnection GetConnection()
        {
            var connection = new SqlConnection(GetConnectionString());
            if (connection == null)
                throw new ConfigurationErrorsException("Failed to create connection");
            connection.Open();
            return connection;
        }
        public static List<Dictionary<string, object>> ToList(this IDataReader dataReader)
        {
            var list = new List<Dictionary<string, object>>();
            while (dataReader.Read())
            {
                var dictionary = Enumerable.Range(0, dataReader.FieldCount)
                    .ToDictionary(dataReader.GetName, i => dataReader.IsDBNull(i) ? null : dataReader.GetValue(i));
                list.Add(dictionary);
            }
            return list;
        }
    }
}
