#ifndef SESSION_H
#define SESSION_H

/*
 * session.h - Peer session state
 *
 * Responsible for:
 *   - Tracking outgoing sequence numbers (per-packet, for framing)
 *   - Anti-replay: a sliding window of recently-seen incoming sequence numbers
 *
 * Design note: start with a single fixed peer (point-to-point) for v1.
 * Multi-peer support is a stretch goal (would turn this into a table
 * keyed by peer address/id).
 */

#include <stdint.h>

#define REPLAY_WINDOW_SIZE 64  /* bits in the sliding window bitmap */

typedef struct {
    uint64_t send_seq;                 /* next sequence number to use when sending */
    uint64_t recv_highest_seq;         /* highest sequence number seen so far */
    uint64_t replay_bitmap;            /* bitmap of recently-seen seq numbers */
} session_ctx_t;

/* Initializes a fresh session (sequence counters zeroed). */
void session_init(session_ctx_t *sess);

/* Returns the next sequence number to attach to an outgoing packet,
 * and increments the internal counter. */
uint64_t session_next_send_seq(session_ctx_t *sess);

/* Checks an incoming sequence number against the replay window.
 * Returns 1 if the packet is NEW (should be accepted and the window
 * updated), 0 if it's a replay/too-old (should be dropped). */
int session_check_replay(session_ctx_t *sess, uint64_t seq);

#endif /* SESSION_H */
