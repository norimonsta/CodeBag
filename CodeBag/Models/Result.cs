using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Models
{
    public struct Result
    {
        public bool IsSuccess { get { return string.IsNullOrEmpty(ErrorMessage); } }
        public string ErrorMessage { get; private set; }
        public Exception Exception { get; private set; }

        public static Result Success() { return new Result(); }
        public static Result Error(string errorMessage) { return new Result { ErrorMessage = errorMessage }; }
    }

    public struct Result<T>
    {
        public bool IsSuccess { get { return string.IsNullOrEmpty(ErrorMessage); } }
        public string ErrorMessage { get; private set; }
        public T Value { get; private set; }
        public Exception Exception { get; private set; }

        public static Result<T> Success(T value) { return new Result<T> { Value = value }; }
        public static Result<T> Error(string errorMessage) { return new Result<T> { ErrorMessage = errorMessage }; }
        public static Result<T> Error(string errorMessage, Exception exception)
        {
            return new Result<T>
            {
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }
}
