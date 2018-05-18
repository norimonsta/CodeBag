using CodeBag.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace CodeBag.MvcAttributes.ValidateModelState
{
    //Copied from https://github.com/benfoster/Fabrik.Common/blob/master/src/Fabrik.Common.Web/Filters/ValidateModelStateAttribute.cs

    /// <summary>
    /// An ActionFilter for automatically validating ModelState before a controller action is executed.
    /// Performs a Redirect if ModelState is invalid. Assumes the <see cref="ImportModelStateFromTempDataAttribute"/> is used on the GET action.
    /// </summary>
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = false, Inherited = true)]
    public class ValidateModelStateAttribute : ModelStateTempDataTransfer
    {
        public override void OnActionExecuting(ActionExecutingContext filterContext)
        {
            if (!filterContext.Controller.ViewData.ModelState.IsValid)
            {
                if (filterContext.HttpContext.Request.IsAjaxRequest())
                {
                    ProcessAjax(filterContext);
                }
                else
                {
                    ProcessNormal(filterContext);
                }
            }

            base.OnActionExecuting(filterContext);
        }

        protected virtual void ProcessNormal(ActionExecutingContext filterContext)
        {
            // Export ModelState to TempData so it's available on next request
            ExportModelStateToTempData(filterContext);

            // redirect back to GET action
            filterContext.Result = new RedirectToRouteResult(filterContext.RouteData.Values);
        }

        protected virtual void ProcessAjax(ActionExecutingContext filterContext)
        {
            //var errors = filterContext.Controller.ViewData.ModelState.ToSerializableDictionary();
            //var json = new JavaScriptSerializer().Serialize(errors);

            filterContext.HttpContext.Response.StatusCode = (int)HttpStatusCode.BadRequest;

            //In case status code is not 200, IIS might respond with its own custom error and we loose the validation information.
            filterContext.HttpContext.Response.TrySkipIisCustomErrors = true;

            filterContext.Result = new JsonResult
            {
                Data = new { Errors = filterContext.Controller.ViewData.ModelState.ToAjaxErrors() }
            };
        }
    }
}
