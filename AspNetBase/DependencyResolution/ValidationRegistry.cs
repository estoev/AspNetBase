using System;
using System.Linq;
using System.Reflection;
using AspNetBase.Helpers;
using FluentValidation;
using StructureMap.Configuration.DSL;
using StructureMap.Pipeline;

namespace AspNetBase.DependencyResolution
{
    public class ValidationRegistry : Registry
    {
        public ValidationRegistry()
        {
            AssemblyScanner.FindValidatorsInAssembly(Assembly.GetCallingAssembly())
                .ForEach(result =>
                         {
                             if (! Attribute.IsDefined(result.ValidatorType, typeof (DontAutoWireupAttribute)))
                             {
                                 {
                                     For(result.InterfaceType)
                                         .LifecycleIs(new UniquePerRequestLifecycle())
                                         .Use(result.ValidatorType);
                                 }
                             }
                         });
        }
    }
}