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
 *
 * Sequence numbers start at (unix_seconds << 32), not 0. With a static
 * key and no handshake, a restarted peer would otherwise start again at
 * 0 and every packet would look like a replay to the other side. Using
 * the clock keeps numbers increasing across restarts (as long as the
 * clock doesn't go backwards and we send < 4 billion packets/second).
 * Sequence number 0 is never valid.
 */

#include <stdint.h>

#define REPLAY_WINDOW_SIZE 64  /* bits in the sliding window bitmap */

typedef struct {
    uint64_t send_seq;          /* last sequence number we sent */
    uint64_t recv_highest_seq;  /* highest sequence number accepted so far */
    uint64_t replay_bitmap;     /* bit i set = (recv_highest_seq - i) was seen */
} session_ctx_t;

/* Initializes a fresh session. */
void session_init(session_ctx_t *sess);

/* Returns the next sequence number to attach to an outgoing packet. */
uint64_t session_next_send_seq(session_ctx_t *sess);

/* Checks an incoming sequence number against the replay window.
 * Returns 1 if the packet is NEW (and records it as seen), 0 if it's a
 * replay or too old (should be dropped).
 * Only call this AFTER the packet has been authenticated, otherwise a
 * forged packet with a huge seq could push the window forward. */
int session_check_replay(session_ctx_t *sess, uint64_t seq);

#endif /* SESSION_H */
