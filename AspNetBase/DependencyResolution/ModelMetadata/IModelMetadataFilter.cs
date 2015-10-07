using System;
using System.Collections.Generic;

namespace AspNetBase.DependencyResolution.ModelMetadata
{
    public interface IModelMetadataFilter
    {
        void TransformMetadata(System.Web.Mvc.ModelMetadata metadata,
            IEnumerable<Attribute> attributes);
    }
}