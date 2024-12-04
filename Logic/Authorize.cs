using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;

namespace Logic
{
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public class AuthorizeAttribute : Attribute, IAuthorizationFilter
    {
        private readonly Auth2Validation _validation = new();
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var headers = context.HttpContext.Request.Headers;

            try
            {
                //this value has Bearer XXXXXXXXXXXXXXXXX
                //but it could be empty here so we would replace the first bit
                //here
                string bearerToken = headers.Authorization!;
                _validation.ValidateToken(bearerToken.Replace("Bearer ", ""));
            }
            catch (Exception perr)
            {


                string error_message = perr.Message;
                context.Result = new JsonResult(new { message = error_message, trace_id = new Guid().ToString() }) { StatusCode = StatusCodes.Status401Unauthorized };

            }

        }

    }
}