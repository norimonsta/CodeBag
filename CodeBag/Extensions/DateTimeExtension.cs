using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Extensions
{
    public static class DateTimeExtension
    {
        public static DateTime AddWorkdays(this DateTime originalDate, int workDays)
        {
            var newDate = originalDate;
            while (workDays > 0)
            {
                newDate = newDate.AddDays(1);
                if (newDate.DayOfWeek < DayOfWeek.Saturday &&
                    newDate.DayOfWeek > DayOfWeek.Sunday &&
                    !newDate.IsHoliday())
                    workDays--;
            }
            return newDate;
        }

        public static bool IsHoliday(this DateTime originalDate)
        {
            //TODO: import holidays
            return false;
        }
    }
}
