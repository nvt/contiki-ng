#include "contiki-memory.h"
#include <string.h>
#include <stdio.h>

void * contiki_calloc( size_t nmemb, size_t size )
{
  void* ptr = heapmem_alloc(nmemb * size);
  if(ptr){
    memset(ptr, 0, nmemb * size);
    return ptr;
  }else{
    return NULL;
  }
}

void contiki_free( void * ptr )
{
  heapmem_free(ptr);
}
