# CP v2 delivery state machine (normative)

Single source of truth for receipt, operation, cursor and desired-state rules.
Code follows this doc: `cpv2/delivery.py` (`batch`, `acknowledge`,
`valid_operation`, `snapshot`), `cpv2/core.py` (`operation`,
`settings_change`, `read_operation`, `event`), `cpv2/auth.py`
(`authenticate`), `cpv2/legacy.py` (`import_u1`). Where code and this doc
disagree, fix the code.

## Records

- An operation is accepted atomically with desired revision (where
  applicable), outbox rows, and acceptance audit/history.
- A logical envelope is `(consumer, epoch, sequence)`: fixed operation,
  target generation, desired revision and payload hash. The physical outbox
  PK is `(consumer_id, sequence)`; epoch is carried on the row and every
  comparison, never assumed from the key.
- Per-consumer receipts persist `received`, `validated`, `applied`,
  `effective`, `rejected`, `unknown`. `accepted` is the implicit initial
  state (no row). `expired`/`superseded` are dispatcher decisions, never
  accepted ACK states.
- A settings head `(namespace, environment, backend, target, revision)` is
  durable desired authority, independent of any operation deadline.

## Per-consumer transitions

| From | Next fact | Conditions |
|---|---|---|
| implicit accepted | received | bound executor, exact envelope, next contiguous sequence, permission/deadline/head valid for new work |
| implicit accepted | rejected / unknown | settles next contiguous envelope without authorizing execution; unknown may be the first remotely reported fact after a crash |
| received | validated | exact envelope, received predecessor, eligibility still valid for new work |
| received | rejected / unknown | no confirmed application |
| validated | applied | executor reports actual application; later revocation/deadline/supersede never erases it |
| validated | rejected / unknown | no confirmed application |
| applied | effective / unknown | observed effectiveness or uncertainty; `rejected` after `applied`/`effective` is a conflict, never a state change |
| effective / rejected / unknown | exact duplicate only | same persisted receipt fingerprint succeeds; changed duplicate or new transition conflicts |

The receipt fingerprint covers every ack field except `output` (command text
stored with the receipt): an executor that restarted reposts its decided state
without it and still matches.

Post-policy `received`/`validated` are recorded as historical facts: the
executor reports what it did before losing authorization. Recording grants
nothing; execution stays fenced at `batch` time. A historical-fact upload is
never a fresh permission grant.

## Operation reduction

Computed under the operation row lock from ALL required consumer receipts:

1. All target states equal: that state.
2. Mixed rejected/unknown, or effects mixed with pending: `partial`.
3. Otherwise: least progress across targets.

`batch` settlement uses the same reduction (known effects AND uncertainty
are preserved; authorization failure is a per-frame delivery verdict, never
a rewrite of shared fact). `read_operation` never lazily expires an
operation with no outbox rows: with nothing queued there is no failed
delivery to declare. Async operations need all target confirmations for
`effective`; a consumer-less settings commit stays `accepted` with its head
intact.

## Cursor and generation

- `received_cursor` is the largest contiguous prefix covered by
  received/rejected/unknown receipts, never the largest seen sequence.
- New received/first-terminal receipts enter at cursor+1 only; reconnects
  replay the durable cursor, never advance it from a socket event id.
- Generation/epoch replacement fences old effects. Retired frames settle
  only through a documented endpoint identity — historical
  `(record.epoch, record.generation)` or current `(consumer.epoch,
  consumer.generation)` — with a terminal (`rejected`/`unknown`) receipt.
  Anything else (new work, unrelated generation, changed duplicate) is a
  mismatch. Exact historical duplicates succeed before any new-transition
  generation/epoch rule.
- Snapshot reports desired state plus the received cursor from one
  repeatable-read transaction, sorted by `(namespace, target)` so the hash
  is order-stable. It never acknowledges work.

## Representation boundary

Requests are validated as representable BEFORE hashing or inserting: no NUL,
no lone surrogates, integers within signed bigint, revision counters
bounded with explicit exhaustion handling. Unrepresentable input is 4xx,
never a hash exception or database error.
