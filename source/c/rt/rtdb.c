#include "rt/rtdb.h"
#include <stdio.h>

#define RTDB_NO_FREE 0x1

#define RTDB_TYPE_BOOL 1
#define RTDB_TYPE_STR 2
#define RTDB_TYPE_STRARR 3

#define RTDB_RESERVE_SIZE 128

struct _isdite_rt_rtdb_key
{
  int iType;
  int iFlags;
  void * pData;
  const char * csName;
};

struct _isdite_rt_rtdb_key_string
{
  const char * sData;
};

struct _isdite_rt_rtdb_key_integer
{
  int iData;
};

struct _isdite_rt_rtdb_node
{
  int iFlags;

  const char * csNodeName;

  unsigned int uiChildNodeCount;
  struct _isdite_rt_rtdb_node * pChildNodes[RTDB_RESERVE_SIZE];

  unsigned int uiSubKeyCount;
  struct _isdite_rt_rtdb_key * pSubKeys[RTDB_RESERVE_SIZE];
};

static struct _isdite_rt_rtdb_key ARG_PARAM_POOL[RTDB_RESERVE_SIZE];

static const char * ARG_NODE_NAME = "ARG";
static struct _isdite_rt_rtdb_node ARG_NODE;

static const char * ROOT_NODE_NAME = "ROOT";
static struct _isdite_rt_rtdb_node ROOT_NODE;

int isdite_rt_dbInitialize(unsigned int uiArgCount, char * pArgVal[])
{
  ROOT_NODE.iFlags = RTDB_NO_FREE;
  ROOT_NODE.csNodeName = ROOT_NODE_NAME;
  ROOT_NODE.uiChildNodeCount = 1;
  ROOT_NODE.uiSubKeyCount = 0;
  ROOT_NODE.pChildNodes[0] = &ARG_NODE;

  ARG_NODE.iFlags = RTDB_NO_FREE;
  ARG_NODE.csNodeName = ARG_NODE_NAME;
  ARG_NODE.uiChildNodeCount = 0;
  ARG_NODE.uiSubKeyCount = 0;

  for(unsigned int i = 0; i < uiArgCount; i++)
  {
    if(pArgVal[i][0] != '-')
    {
      // Usage of unbound parameters is not allowed.
      return -1;
    }

    struct _isdite_rt_rtdb_key * pKey =
      &ARG_PARAM_POOL[ARG_NODE.uiSubKeyCount];

    pKey->csName = pArgVal[i] + 1; // Skip -.

    if(i + 1 == uiArgCount || pArgVal[i + 1][0] == '-') // Single logic type.
    {
      printf("PARSING BOOLEAN PARAM %s\n",  pArgVal[i] + 1);
      pKey->iType = RTDB_TYPE_BOOL;
      pKey->pData = (void*)1;
      pKey->iFlags = 0;
    }
    else if(i + 2 < uiArgCount && pArgVal[i + 2][0] != '-') // Array type.
    {
      printf("PARSING ARRAY PARAM %s\n",  pArgVal[i] + 1);
      unsigned int uiArraySize = 2;

      for(unsigned int n = i + 3; n < uiArgCount;n++)
      {
        if(pArgVal[n][0] == '-')
          break;
        uiArraySize++;
      }

      pKey->iType = RTDB_TYPE_STRARR;
      pKey->pData = pArgVal + i + 1;
      pKey->iFlags = uiArraySize;

      for(int i = 0; i < uiArraySize;i++)
      {
        printf("%s\n", ((char**)pKey->pData)[i]);
      }

      i += uiArraySize;
    }
    else // Single value type.
    {
      printf("PARSING SINGLE PARAM %s %s\n",  pArgVal[i] + 1, pArgVal[i + 1]);
      pKey->iType = RTDB_TYPE_STR;
      pKey->pData = pArgVal[i + 1];
      pKey->iFlags = 0;

      i++;
    }

    ARG_NODE.pSubKeys[ARG_NODE.uiSubKeyCount++] = pKey;
  }

  return 0;
}
