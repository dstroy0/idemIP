import TimeDeterminism.Reading
import TimeDeterminism.Ratchet

/-!
# TimeDeterminism, the slot that holds a result

A padded call site has one slot for each thread. The slot holds the pad, the stamp of the held call, the
status that its body gave, and whether a result is held. `call` is one call, as `td_run` does it.

A call to a slot that holds no result reads the clock, runs the body and reads the clock again. Where the pad
has not elapsed, the slot keeps the status and answers busy. A call to a slot that holds a result runs no body.
It reads the clock once, and it answers busy until the pad elapses. Then it gives the kept status.

The theorems: a held slot reads neither the body nor the reading before it, so the input cannot reach its
answer. The status that a held slot gives is the status that the body gave. The pad changes only on a call
that runs the body.
-/

namespace TimeDeterminism

/-- One thread's state for one padded call site. -/
structure Slot where
  pad : Nat
  held : Bool
  status : Nat
  stamp : Nat

/-- What a call answers: busy, or done with the status of the body. -/
inductive Answer
  | busy
  | done (status : Nat)
  deriving DecidableEq

/-- One call. `body` is the status that the body gives, `t0` the reading before the body and `t1` the reading
after it. A held slot reads `t1` alone. -/
def call (walks : Bool) (hi : Nat) (s : Slot) (body t0 t1 : Nat) : Slot × Answer :=
  if s.held then
    if classify s.pad (spent s.stamp t1) = .early then (s, .busy)
    else ({ s with held := false }, .done s.status)
  else
    if classify s.pad (spent t0 t1) = .early then ({ s with held := true, status := body, stamp := t0 }, .busy)
    else ({ s with pad := tune walks hi s.pad (classify s.pad (spent t0 t1)) (spent t0 t1) }, .done body)

/-- A held slot reads neither the body nor the reading before it. -/
theorem held_reads_no_body (walks : Bool) (hi : Nat) (s : Slot) (b b' t0 t0' t1 : Nat) (h : s.held = true) :
    call walks hi s b t0 t1 = call walks hi s b' t0' t1 := by
  simp [call, h]

/-- A held slot gives the status that its body gave, or busy. -/
theorem held_gives_kept (walks : Bool) (hi : Nat) (s : Slot) (b t0 t1 x : Nat) (h : s.held = true)
    (hd : (call walks hi s b t0 t1).2 = .done x) : x = s.status := by
  unfold call at hd
  simp only [h, ite_true] at hd
  split at hd
  · cases hd
  · cases hd; rfl

/-- A held slot never changes its pad. -/
theorem held_keeps_pad (walks : Bool) (hi : Nat) (s : Slot) (b t0 t1 : Nat) (h : s.held = true) :
    (call walks hi s b t0 t1).1.pad = s.pad := by
  unfold call
  simp only [h, ite_true]
  split <;> rfl

/-- A call that keeps the result keeps the status of the body and the reading before it. -/
theorem keep_status (walks : Bool) (hi : Nat) (s : Slot) (b t0 t1 : Nat) (h : s.held = false)
    (he : classify s.pad (spent t0 t1) = .early) :
    (call walks hi s b t0 t1).1.status = b ∧ (call walks hi s b t0 t1).1.stamp = t0 ∧
      (call walks hi s b t0 t1).1.held = true ∧ (call walks hi s b t0 t1).2 = .busy := by
  simp [call, h, he]

/-- A held result goes when the pad elapses: the slot then holds no result. -/
theorem release_clears (walks : Bool) (hi : Nat) (s : Slot) (b t0 t1 : Nat) (h : s.held = true)
    (hn : classify s.pad (spent s.stamp t1) ≠ .early) :
    (call walks hi s b t0 t1).1.held = false ∧ (call walks hi s b t0 t1).2 = .done s.status := by
  simp [call, h, hn]

end TimeDeterminism
