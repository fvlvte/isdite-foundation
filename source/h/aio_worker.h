#ifndef ISDITE_FOUNDATION_AIOWORKER
#define ISDITE_FOUNDATION_AIOWORKER

#define ISDITE_AIO_BUFF_SZ 512

struct isdite_fn_aio_task
{
  int status;
  void * job;
  u_int8_t param_buffer[sizeof(int) * 512]; // alignment for speed
  void * ext_param;
};

struct isdite_fn_aio
{
  int worker_count;

  int task_list_top;
  struct isdite_fn_aio_task * task_list;
};

struct isdite_fn_aio * isdite_fn_aio_init(int workerCount, int reserveSizeBase);
void isdite_fn_aio_destroy(struct isdite_fn_aio * instance);

void isdite_fn_aio_enqueue(struct isdite_fn_aio * inst, void * task, void * param, int paramSz, void * paramEx);
void isdite_fn_aio_enqueueTs(struct isdite_fn_aio * inst, void * task, void * param, int paramSz, void * paramEx);

struct isdite_fn_aio_task * isdite_fn_aio_reserve(void);
struct isdite_fn_aio_task * isdite_fn_aio_reserveTs(void);
void isdite_fn_aio_post(struct isdite_fn_aio_task * target);

#endif
