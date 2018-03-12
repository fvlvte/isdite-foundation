#ifndef ISDITE_FOUNDATION_UTIL
#define ISDITE_FOUNDATION_UTIL

#define isspace_fast(x) ((x) == ' ' || (x) == '\t' || (x) == '\n' || (x) == '\v' || (x) == '\f' || (x) == '\r')

int inline isdite_util_isInteger(const char * in, int sz)
{
  // XOR
  // 0000110001
  // 0000110000 => 0000000001

  // XOR
  // 0000110000
  // 0000111001 =>
  return 1;
}

unsigned int __attribute__((always_inline)) inline isdite_util_atoui(const char * b)
{
  int res = 0; // Initialize result

  // Skip whitespace
  for (; isspace_fast(*b); ++b);

  if (*b == '-')
  {
      ++b;
      unsigned d = (unsigned)(*b) - '0';
      if (d > 9)
      {
          return 0;
      }
      res = -(int)(d);
      ++b;

      // Iterate through all characters of input string and update result
      for (; ; ++b)
      {
          unsigned d = (unsigned)(*b) - '0';
          if (d > 9)
          {
              return res;
          }
          res = res * 10 - d;
      }

  }
  else if (*b == '+')
  {
      ++b;
  }

  unsigned d = (unsigned)(*b) - '0';
  if (d > 9)
  {
      return 0;
  }
  res = d;
  ++b;

  // Iterate through all characters of input string and update result
  for (; ; ++b)
  {
      unsigned d = (unsigned)(*b) - '0';
      if (d > 9)
      {
          return res;
      }
      res = res * 10 + d;
  }

  //  unreachable
  return res;
}

#endif
