# `with_transaction` is by-value: the async-closure HRTB limitation

`rs-repository-utils::BaseRepository::with_transaction` passes the pooled
connection to its closure **by value**; the closure opens, commits, and
(by dropping on error) rolls back its own transaction. The natural cleaner
shape — the helper owns begin/commit/rollback and hands the closure a
`&Transaction` — is not expressible on current Rust. This ADR records why.

## Decisions

1. **The closure receives the connection by value and owns the transaction
   lifecycle.** `with_transaction(op, table, |client| async move { let tx =
   client.transaction().await?; …; tx.commit().await?; Ok(…) })`. The helper
   adds pool acquisition, the circuit breaker, and observer reporting
   (op/table/duration/success). On error the closure returns `Err`, the
   transaction is dropped (rolled back) and the connection returns to the
   pool.

2. **The closure-over-`&Transaction` form is rejected as unbuildable.** An
   inline async closure's returned future is a concrete type capturing the
   transaction reference at a fixed lifetime, so it cannot satisfy
   `for<'tx> AsyncFnOnce(&'tx Transaction<'tx>)` — the compiler rejects every
   call site with E0700 ("lifetime may not live long enough") / "implementation
   of AsyncFnOnce is not general enough". A named `async fn` item *does*
   satisfy the bound, but `AsyncFnOnce` takes a single argument, so a
   transaction body that captures surrounding state (the normal case: the
   user id, credential id, passkey, name…) cannot be expressed — extra
   parameters break the trait's arity. Only the by-value form supports
   capturing bodies.

3. **This explains the removal of the original `execute_transaction`.** That
   method (removed in the breaking by-value refactor) had exactly this
   unusable `for<'tx> AsyncFnOnce(&'tx Transaction)` bound: its definition
   compiled, but no callable closure form existed, so it was dead code. The
   removal was correct; the reason was the HRTB limitation, not (as initially
   suspected) a borrow-checker regression.

4. **The resulting contract hazard is accepted and documented.** Because the
   closure owns the transaction, returning `Ok` without calling `commit()`
   silently rolls back the writes while the observer records success. This is
   the unavoidable cost of usable transaction closures and matches the
   broader ecosystem (sqlx, diesel-async, tokio-postgres users all open and
   commit manually). The library doc-comment states the contract explicitly;
   the two rs-server call sites (`complete_registration`,
   `remove_credential`) commit correctly.

## Rejected alternative

A `Tx` wrapper that commits or rolls back in `Drop` was considered. It does
not remove the hazard — the closure still decides the outcome — and it
either silently commits a forgotten rollback or silently rolls back a
forgotten commit, both worse than an explicit `commit()` call.
