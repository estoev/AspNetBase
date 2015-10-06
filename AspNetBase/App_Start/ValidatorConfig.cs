using System.Reflection.Emit;
using System.Web.Mvc;
using AspNetBase.DependencyResolution;
using AspNetBase.Helpers;
using FluentValidation;
using FluentValidation.Mvc;

namespace AspNetBase
{
    public static class ValidatorConfig
    {
        public static void Init()
        {
            var factory = new StructureMapValidatorFactory();
            ModelValidatorProviders.Providers.Add(new FluentValidationModelValidatorProvider(factory));
            DataAnnotationsModelValidatorProvider.AddImplicitRequiredAttributeForValueTypes = false;
        }
    }
}