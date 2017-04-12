using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Extensions
{
    public static class ObjectExtension
    {
        public static T ToSafe<T>(this object obj)
        {
            if (obj == null)
                return default(T);

            var converter = TypeDescriptor.GetConverter(typeof(T));
            try
            {
                return (T)converter.ConvertFromString(obj.ToString());
            }
            catch
            {
                return default(T);
            }
        }

    }
}
