﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Extensions
{
    public static class EnumExtension
    {
        public static string GetDescription(this Enum value)
        {
            var field = value.GetType().GetField(value.ToString());

            var attribute
                    = Attribute.GetCustomAttribute(field, typeof(DescriptionAttribute))
                        as DescriptionAttribute;

            return attribute == null ? value.ToString() : attribute.Description;
        }
    }
}
