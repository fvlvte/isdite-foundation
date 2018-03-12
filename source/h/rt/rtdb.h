#ifndef ISDITE_FOUNDATION_RT_RTDB
#define ISDITE_FOUNDATION_RT_RTDB

/*
  <name>isdite_rt_dbInitialize</name>
  <return>integer (int)</return>
  <returnDesc>Zero if success, error code otherwise.</returnDesc>
  <param>Not available.</param>
  <desc>Initializes runtime database for command line parameters and other shared runtime informations.</desc>
*/
int isdite_rt_dbInitialize(void);
void isdite_rt_dbFree(void);

void isdite_rt_dbEnterSharedEnvironment(void);
void isdite_rt_dbLeaveSharedEnvironment(void);

void isdite_rt_dbGet(void);
void isdite_rt_dbSet(void);

#endif
