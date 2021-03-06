﻿using System;

namespace AspNetBase.Services
{
    public interface ICacheService
    {
        T Get<T>(string cacheId, Func<T> getItemCallback, string invalidateKeys = null,
            DateTime? absoluteExpiration = null, TimeSpan? slidingExpiration = null) where T : class;

        void Remove(string cacheId);

        void Invalidate(string invalidateKeys);
    }
}