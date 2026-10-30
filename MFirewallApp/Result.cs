using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace MFirewallApp
{
    public class Result<TError>
    {
        

        public TError? Error { get; init; }

        public bool IsSuccess { get; init; } 

        private Result( TError? error, bool isSucces)
        {
           
            Error = error;
            IsSuccess = isSucces;
        }
        public static Result< TError> Success => new Result<TError>(default, true);
        public static Result<TError> Failure(TError error) => new Result<TError>(error, false); 
    } 
    
}