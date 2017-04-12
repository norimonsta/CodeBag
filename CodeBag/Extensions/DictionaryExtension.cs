using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Extensions
{
    public static class DictionaryExtension
    {
        public static T GetValue<T>(this Dictionary<string, object> dictionary, string keyName)
        {
            if (dictionary == null) return default(T);
            return dictionary[keyName].ToSafe<T>();
        }
    }
}
