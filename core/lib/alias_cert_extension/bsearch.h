// Copied from https://sourceware.org/git/?p=glibc.git;a=blob_plain;f=bits/stdlib-bsearch.h;h=4dcf90c99a998dd0f22ddcdae1eb110e9721a793;hb=HEAD

typedef int (*__compar_fn_t) (const void *, const void *);

static void *
bsearch (const void *__key, const void *__base, size_t __nmemb, size_t __size,
	 __compar_fn_t __compar)
{
  size_t __l, __u, __idx;
  const void *__p;
  int __comparison;

  __l = 0;
  __u = __nmemb;
  while (__l < __u)
    {
      __idx = (__l + __u) / 2;
      __p = (const void *) (((const char *) __base) + (__idx * __size));
      __comparison = (*__compar) (__key, __p);
      if (__comparison < 0)
	__u = __idx;
      else if (__comparison > 0)
	__l = __idx + 1;
      else
	{
	  return (void *) __p;
	}
    }

  return NULL;
}
