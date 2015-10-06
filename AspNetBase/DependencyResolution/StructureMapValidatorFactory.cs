using System;
using FluentValidation;

namespace AspNetBase.DependencyResolution
{
    public class StructureMapValidatorFactory : ValidatorFactoryBase
    {
        public override IValidator CreateInstance(Type validatorType)
        {
            return IoC.StructureMapResolver.Container.TryGetInstance(validatorType) as IValidator;
        }
    }
}