#include "ierr.h"

__thread int LAST_ERROR = ISERR_NONE;

void isdite_fdn_raiseThreadIntError(int errorDesc)
{
  LAST_ERROR = errorDesc;
}

// TODO: Expand.
