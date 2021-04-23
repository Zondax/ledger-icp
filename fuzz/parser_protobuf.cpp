#include <cassert>
#include <cstdint>

#include "parser.h"
#include "pb_decode.h"
#include "protobuf/dfinity.pb.h"


#ifdef NDEBUG
#error "This fuzz target won't work correctly with NDEBUG defined, which will cause asserts to be eliminated"
#endif


using std::size_t;

static char PARSER_KEY[16384];
static char PARSER_VALUE[16384];

parser_tx_t txObj;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    bool status;

    /* Allocate space for the decoded message. */
    SendRequest request = SendRequest_init_zero;

    /* Create a stream that reads from the buffer. */
    pb_istream_t stream = pb_istream_from_buffer(data, size);

    /* Now we are ready to decode the message. */
    pb_decode(&stream, SendRequest_fields, &request);

    return 0;
}
