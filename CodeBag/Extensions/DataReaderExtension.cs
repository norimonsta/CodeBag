using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Extensions
{
    public static class DataReaderExtension
    {
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
