using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace AspNetBase.Helpers
{
    public static class MiscHelpers
    {
        private static readonly Random _random = new Random();

        public static T? AsNullIfDefault<T>(this T value) where T : struct
        {
            if (value.Equals(default(T)))
                return null;
            return value;
        }

        public static string RandomText(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var result = new string(
                Enumerable.Repeat(chars, length)
                          .Select(s => s[_random.Next(s.Length)])
                          .ToArray());

            return result;
        }

        public static IEnumerable<DateTime> EachDay(this DateTime from, DateTime thru)
        {
            for (var day = from.Date; day.Date <= thru.Date; day = day.AddDays(1))
                yield return day;
        }

        public static int GetOverlappingDays(DateTime firstStart, DateTime firstEnd, DateTime secondStart, DateTime secondEnd)
        {
            DateTime maxStart = firstStart > secondStart ? firstStart.Date : secondStart.Date;
            DateTime minEnd = firstEnd < secondEnd ? firstEnd.Date : secondEnd.Date;
            TimeSpan interval = minEnd - maxStart;
            double returnValue = interval > TimeSpan.FromSeconds(0) ? interval.TotalDays : 0;
            return (int) Math.Round(returnValue);
        }
    }
}