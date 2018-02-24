#ifndef ISDITE_FOUNDATION_IERR
#define ISDITE_FOUNDATION_IERR
// Internal error helper.

#define ISERR_NONE 0
#define ISERR_OOM 100 // Out of memory

void isdite_fdn_raiseThreadIntError(int errorDesc);


#endif
