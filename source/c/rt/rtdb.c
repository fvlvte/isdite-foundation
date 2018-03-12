#include "rt/rtdb.h"

struct _isdite_rt_rtdb_key
{
  int iType;
  void * iData;
  char * sName;
};

struct _isdite_rt_rtdb_key_string
{
  const char * sData;
}

struct _isdite_rt_rtdb_key_integer
{
  int iData;
}

struct _isdite_rt_rtdb_node
{
  char * sNodeName;
  struct _isdite_rt_rtdb_node * pChildNodes[128];
  struct _isdite_rt_rtdb_key * pSubKeys[128];
};
