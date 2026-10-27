#include "session.h"

#include <time.h>

/* session.c - see include/session.h for the contract */

void session_init(session_ctx_t *sess) {
    sess->send_seq = (uint64_t)time(NULL) << 32;
    sess->recv_highest_seq = 0;
    sess->replay_bitmap = 0;
}

uint64_t session_next_send_seq(session_ctx_t *sess) {
    return ++sess->send_seq;
}

/*
 * The window covers the 64 sequence numbers ending at recv_highest_seq:
 *
 *   bit 0  -> recv_highest_seq
 *   bit 1  -> recv_highest_seq - 1
 *   ...
 *   bit 63 -> recv_highest_seq - 63
 *
 * UDP can reorder packets, so we accept anything new inside the window,
 * not just strictly increasing numbers.
 */
int session_check_replay(session_ctx_t *sess, uint64_t seq) {
    if (seq == 0) {
        return 0;
    }

    if (seq > sess->recv_highest_seq) {
        /* Newer than anything seen: slide the window forward. */
        uint64_t shift = seq - sess->recv_highest_seq;
        sess->replay_bitmap = shift >= REPLAY_WINDOW_SIZE ? 0 : sess->replay_bitmap << shift;
        sess->replay_bitmap |= 1;  /* mark seq itself (bit 0) */
        sess->recv_highest_seq = seq;
        return 1;
    }

    uint64_t offset = sess->recv_highest_seq - seq;
    if (offset >= REPLAY_WINDOW_SIZE) {
        return 0;  /* too old to tell, drop it */
    }

    uint64_t bit = 1ULL << offset;
    if (sess->replay_bitmap & bit) {
        return 0;  /* already seen: replay */
    }
    sess->replay_bitmap |= bit;
    return 1;
}
