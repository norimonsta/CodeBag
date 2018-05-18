using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Models
{
    public class AjaxError
    {
        /// <summary>
        /// Gets or sets the control unique identifier.
        /// </summary>
        /// <value>
        /// The control unique identifier.
        /// </value>
        /// <remarks>
        /// Refers to the ID of the DOM object that triggered the error.
        /// </remarks>
        public string ControlId { get; set; }

        public string ErrorMessage { get; set; }
    }
}
