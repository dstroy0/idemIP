/-!
# TimeDeterminism, the reading of the clock

The clock counts ticks in 32 bits, so a reading is the true time modulo `M`. The C takes the unsigned
difference of two readings, `now - stamp` on `uint32_t`. That difference never passes the true time between
the two readings. It equals the true time while the true time stays below `M`.

The four states compare that difference with the pad. A state other than early says that the pad elapsed,
because the difference never passes the true time. So a release never comes early, across a wrap too.
-/

namespace TimeDeterminism

/-- The modulus of a reading. A reading is a `uint32_t`. -/
def M : Nat := 4294967296

/-- The unsigned difference of the readings at true times `t0` and `t1`, as `now - stamp` on `uint32_t`. -/
def spent (t0 t1 : Nat) : Nat := (t1 % M + M - t0 % M) % M

/-- The difference is the true time between the readings, modulo `M`. -/
theorem spent_eq (t0 t1 : Nat) (h : t0 ≤ t1) : spent t0 t1 = (t1 - t0) % M := by
  unfold spent M
  omega

/-- The difference never passes the true time between the readings. -/
theorem spent_le (t0 t1 : Nat) (h : t0 ≤ t1) : spent t0 t1 ≤ t1 - t0 := by
  rw [spent_eq t0 t1 h]
  exact Nat.mod_le _ _

/-- The difference is the true time while the true time stays below `M`. -/
theorem spent_exact (t0 t1 : Nat) (h : t0 ≤ t1) (hm : t1 - t0 < M) : spent t0 t1 = t1 - t0 := by
  rw [spent_eq t0 t1 h]
  exact Nat.mod_eq_of_lt hm

/-- The subtraction on `BitVec 32` that the C does is `spent`. -/
theorem spent_bitvec (t0 t1 : Nat) :
    (BitVec.ofNat 32 t1 - BitVec.ofNat 32 t0).toNat = spent t0 t1 := by
  simp only [BitVec.toNat_sub, BitVec.toNat_ofNat, spent, M]
  omega

/-- Where a pass stands against its pad. The C enum `IdemIpClockPad` has the same four values. -/
inductive Pad
  | unset
  | early
  | met
  | over
  deriving DecidableEq, Repr

/-- The state of a pass that spent `s` ticks against a pad of `pad` ticks, as `td_pad_state` gives it. -/
def classify (pad s : Nat) : Pad :=
  if pad = 0 then .unset else if s < pad then .early else if s = pad then .met else .over

/-- A state other than early, with a pad set, says that the pad elapsed in true time. -/
theorem never_early (pad t0 t1 : Nat) (h : t0 ≤ t1) (hp : pad ≠ 0)
    (hs : classify pad (spent t0 t1) ≠ .early) : t0 + pad ≤ t1 := by
  have hle := spent_le t0 t1 h
  have hnot : ¬ spent t0 t1 < pad := by
    intro hlt
    apply hs
    simp [classify, hp, hlt]
  omega

/-- The early state says that the difference is below the pad. -/
theorem early_lt (pad s : Nat) (h : classify pad s = .early) : s < pad := by
  unfold classify at h
  split at h
  · cases h
  · split at h
    · assumption
    · split at h <;> cases h

/-- The over state says that the difference passes the pad. -/
theorem over_gt (pad s : Nat) (h : classify pad s = .over) : pad < s := by
  unfold classify at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · cases h
      · omega

/-- Below the pad, with a pad set, the state is early. -/
theorem classify_early (pad s : Nat) (hp : pad ≠ 0) (h : s < pad) : classify pad s = .early := by
  simp [classify, hp, h]

end TimeDeterminism
