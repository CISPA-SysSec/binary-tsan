#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>

int stop;

static void* busy(void *p) {
  while (__atomic_load_n(&stop, __ATOMIC_RELAXED) == 0) {
  }
  return 0;
}

int main() {

  pthread_t th;
  pthread_create(&th, 0, busy, 0);

  __atomic_store_n(&stop, 1, __ATOMIC_RELAXED);
  pthread_join(th, 0);

  return 0;
}
