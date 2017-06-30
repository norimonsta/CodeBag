using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Text;
using System.Threading.Tasks;

namespace CodeBag.Helpers
{
    internal static class ReflectionHelper
    {
        public delegate object ConstructorDelegate();


        //This is method that leverage dynamic method and reflect to allow instantiating objects of any type at runtime.
        //Similar to Activator.CreateInstance but with much better performance. Almost as fast as instantiating using class constructor without reflection (e.g. new StringBuilder()).
        //To use this method, provide the method with the type name you intend to instantiate and execute the delegate return by this method.
        //E.g. var constructor = GetConstructor("System.Text.StringBuilder");
        //var obj = constructor();
        //Probably not worth it unless you are instantiating a lot of objects of the same type.
        public static ConstructorDelegate GetConstructor(string typeName)
        {
            // get the default constructor of the type
            Type t = Type.GetType(typeName);
            ConstructorInfo ctor = t.GetConstructor(new Type[0]);

            // create a new dynamic method that constructs and returns the type
            string methodName = t.Name + "Ctor";
            DynamicMethod dm = new DynamicMethod(methodName, t, new Type[0], typeof(Activator));
            ILGenerator lgen = dm.GetILGenerator();
            lgen.Emit(OpCodes.Newobj, ctor);
            lgen.Emit(OpCodes.Ret);

            //add delegate to dictionary and return
            ConstructorDelegate creator = (ConstructorDelegate)dm.CreateDelegate(typeof(ConstructorDelegate));

            //return a delegate to the method
            return creator;
        }
    }
}
