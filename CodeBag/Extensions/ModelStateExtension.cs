using CodeBag.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web.Mvc;

namespace CodeBag.Extensions
{
    public static class ModelStateExtension
    {
        public static void AddValidationError(this ModelStateDictionary modelStateDictionary, string key, string message)
        {
            if (!modelStateDictionary.ContainsKey(key))
            {
                ModelState modelState = new ModelState();
                modelStateDictionary.Add(key, modelState);
            }
            modelStateDictionary.AddModelError(key, message);
        }

        public static void RemoveValidationError(this ModelStateDictionary modelStateDictionary, string key)
        {
            if (modelStateDictionary.ContainsKey(key))
            {
                modelStateDictionary.Remove(key);
            }
        }

        //https://github.com/benfoster/Fabrik.Common/blob/master/src/Fabrik.Common.Web/ModelStateExtensions.cs
        /// <summary>
        /// Converts the <paramref name="modelState"/> to a dictionary that can be easily serialized.
        /// </summary>
        public static IDictionary<string, string[]> ToSerializableDictionary(this ModelStateDictionary modelState)
        {
            return modelState.Where(x => x.Value.Errors.Any()).ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value.Errors.Select(e => e.ErrorMessage).ToArray()
            );
        }

        public static List<AjaxError> ToAjaxErrors(this ModelStateDictionary modelState)
        {
            var ajaxErrors = new List<AjaxError>();
            foreach (var errorCollection in modelState)
            {
                var controlId = errorCollection.Key;

                ajaxErrors.AddRange(
                    errorCollection.Value.Errors.Select(
                        err => new AjaxError
                        {
                            ControlId = controlId,
                            ErrorMessage = err.ErrorMessage
                        }));
            }
            return ajaxErrors;
        }
    }
}
