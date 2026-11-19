import TimeDeterminism.Reading

/-!
# TimeDeterminism, the window of a release

A padded call reads the clock at `t 0` and runs the body. It reads the clock again at `t 1`, after the body.
The caller then calls again at `t 2`, `t 3` and on, and each call reads the clock once. The gap between two
readings is `g` at most. The slot answers busy while the state is early, and the first call with another state
gets the result.

Where the work fits the pad, `t 1 ≤ t 0 + pad`, the release comes in `[t 0 + pad, t 0 + pad + g)`. The bounds
hold the pad and the gap, and the input is not in them. So two inputs whose work fits the pad give releases
less than `g` apart, and the caller sees no more of the input than one gap of its own calls.
-/

namespace TimeDeterminism

section Window

variable (pad g : Nat) (t : Nat → Nat)

/-- The readings never go back. -/
theorem reading_mono (hmono : ∀ j, t j ≤ t (j + 1)) : ∀ j, t 0 ≤ t j := by
  intro j
  induction j with
  | zero => exact Nat.le_refl _
  | succ j ih => exact Nat.le_trans ih (hmono j)

/-- Each reading before the release comes before the pad elapses. -/
theorem before_release (k : Nat) (hp : 0 < pad) (hg : pad + g < M)
    (hmono : ∀ j, t j ≤ t (j + 1)) (hgap : ∀ j, t (j + 1) ≤ t j + g)
    (hbefore : ∀ j, 1 ≤ j → j < k → classify pad (spent (t 0) (t j)) = .early) :
    ∀ j, j < k → t j < t 0 + pad := by
  intro j
  induction j with
  | zero => intro _; omega
  | succ j ih =>
    intro hj
    have hprev := ih (Nat.lt_of_succ_lt hj)
    have h0 := reading_mono t hmono (j + 1)
    have hstep := hgap j
    have hexact : spent (t 0) (t (j + 1)) = t (j + 1) - t 0 :=
      spent_exact (t 0) (t (j + 1)) h0 (by omega)
    have hlt := early_lt pad _ (hbefore (j + 1) (by omega) hj)
    omega

/-- The release comes after the pad elapses, and less than one gap after. -/
theorem release_window (k : Nat) (hp : 0 < pad) (hg0 : 0 < g) (hg : pad + g < M)
    (hmono : ∀ j, t j ≤ t (j + 1)) (hgap : ∀ j, t (j + 1) ≤ t j + g)
    (hwork : t 1 ≤ t 0 + pad) (hk : 1 ≤ k)
    (hbefore : ∀ j, 1 ≤ j → j < k → classify pad (spent (t 0) (t j)) = .early)
    (hrel : classify pad (spent (t 0) (t k)) ≠ .early) :
    t 0 + pad ≤ t k ∧ t k < t 0 + pad + g := by
  have h0 := reading_mono t hmono k
  refine ⟨never_early pad (t 0) (t k) h0 (by omega) hrel, ?_⟩
  cases k with
  | zero => omega
  | succ k =>
    cases k with
    | zero =>
      show t 1 < t 0 + pad + g
      omega
    | succ k =>
      have hprev := before_release pad g t (k + 2) hp hg hmono hgap hbefore (k + 1) (by omega)
      have hstep := hgap (k + 1)
      omega

/-- The first call whose reading reaches the pad gets the result. -/
theorem release_at_pad (k : Nat) (hp : 0 < pad) (hg : pad + g < M)
    (hmono : ∀ j, t j ≤ t (j + 1)) (hgap : ∀ j, t (j + 1) ≤ t j + g)
    (hbefore : ∀ j, 1 ≤ j → j < k → classify pad (spent (t 0) (t j)) = .early)
    (hk : 1 ≤ k) (hreach : t 0 + pad ≤ t k) :
    classify pad (spent (t 0) (t k)) ≠ .early := by
  intro he
  have h0 := reading_mono t hmono k
  have hlt := early_lt pad _ he
  cases k with
  | zero => omega
  | succ k =>
    have hprev := before_release pad g t (k + 1) hp hg hmono hgap hbefore k (by omega)
    have hstep := hgap k
    have hexact : spent (t 0) (t (k + 1)) = t (k + 1) - t 0 :=
      spent_exact (t 0) (t (k + 1)) h0 (by omega)
    omega

end Window

/-- Two inputs whose work fits the pad give releases less than one gap apart, from the same stamp. -/
theorem release_independent (pad g : Nat) (t u : Nat → Nat) (k l : Nat)
    (hp : 0 < pad) (hg0 : 0 < g) (hg : pad + g < M) (hstamp : t 0 = u 0)
    (hmt : ∀ j, t j ≤ t (j + 1)) (hgt : ∀ j, t (j + 1) ≤ t j + g)
    (hmu : ∀ j, u j ≤ u (j + 1)) (hgu : ∀ j, u (j + 1) ≤ u j + g)
    (hwt : t 1 ≤ t 0 + pad) (hwu : u 1 ≤ u 0 + pad) (hk : 1 ≤ k) (hl : 1 ≤ l)
    (hbt : ∀ j, 1 ≤ j → j < k → classify pad (spent (t 0) (t j)) = .early)
    (hbu : ∀ j, 1 ≤ j → j < l → classify pad (spent (u 0) (u j)) = .early)
    (hrt : classify pad (spent (t 0) (t k)) ≠ .early)
    (hru : classify pad (spent (u 0) (u l)) ≠ .early) :
    t k < u l + g ∧ u l < t k + g := by
  have wt := release_window pad g t k hp hg0 hg hmt hgt hwt hk hbt hrt
  have wu := release_window pad g u l hp hg0 hg hmu hgu hwu hl hbu hru
  omega

end TimeDeterminism
