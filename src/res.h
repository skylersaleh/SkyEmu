#ifndef RES_H
#define RES_H 1

#include <stdint.h>

#define SE_NOTO 0
#define SE_KARLA 1
#define SE_FORKAWESOME 2
#define SE_NOTO_ARMENIAN 3
#define SE_NOTO_SANS 4

const uint8_t* se_get_resource(int res_id, uint64_t* size);


#endif
