#include "crypto.h"
#include "coin.h"

int8_t c_fill_principal(uint8_t *output, uint16_t output_len, uint16_t *response_len) {
    answer_t answer = {0};
    uint16_t addr_len = 0;

    if (output_len < DFINITY_PRINCIPAL_LEN){
        *response_len = 0;
        return -1;
    }
    zxerr_t err = crypto_fillAddress((uint8_t*)&answer, sizeof(answer), &addr_len);
    MEMCPY(output, answer.principalBytes, DFINITY_PRINCIPAL_LEN);

    *response_len = DFINITY_PRINCIPAL_LEN;
}
