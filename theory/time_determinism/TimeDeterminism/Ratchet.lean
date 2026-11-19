import TimeDeterminism.Reading

/-!
# TimeDeterminism, the ratchet of a pad

A pad walks up and never down. A pass whose body overran the pad raises the pad to the ticks that the body
spent, and never past the ceiling `hi`. Every other pass leaves the pad as it is. At the LITERAL grade the pad
never walks.

A pad that walks down follows the cost of the inputs that come, and so a pad set by small inputs lets a large
input overrun it. The release of that input then holds its cost. A pad that only walks up keeps the largest cost
that it saw. Each overrun raises the pad past the ticks of that overrun, and the pad stays below the ceiling. So
the overruns of bodies within the ceiling are `hi - pad` at max, over the life of the slot.
-/

namespace TimeDeterminism

/-- The next pad after a pass in state `st` that spent `s` ticks. `walks` is false at the LITERAL grade. -/
def tune (walks : Bool) (hi pad : Nat) (st : Pad) (s : Nat) : Nat :=
  if walks = true ∧ st = .over then min hi s else pad

/-- A pass that is not an overrun leaves the pad as it is. -/
theorem tune_same (walks : Bool) (hi pad : Nat) (st : Pad) (s : Nat) (h : st ≠ .over) :
    tune walks hi pad st s = pad := by
  simp [tune, h]

/-- At the LITERAL grade the pad never moves. -/
theorem tune_pinned (hi pad : Nat) (st : Pad) (s : Nat) : tune false hi pad st s = pad := by
  simp [tune]

/-- The pad never walks down, from a pad within the ceiling. -/
theorem tune_mono (walks : Bool) (hi pad s : Nat) (hh : pad ≤ hi) :
    pad ≤ tune walks hi pad (classify pad s) s := by
  unfold tune
  split
  · next h =>
    have := over_gt pad s h.2
    omega
  · exact Nat.le_refl _

/-- The pad never passes the ceiling. -/
theorem tune_le (walks : Bool) (hi pad : Nat) (st : Pad) (s : Nat) (hh : pad ≤ hi) :
    tune walks hi pad st s ≤ hi := by
  unfold tune
  split <;> omega

/-- An overrun within the ceiling raises the pad to cover it. -/
theorem tune_covers (hi pad s : Nat) (hs : s ≤ hi) (ho : classify pad s = .over) :
    s ≤ tune true hi pad (classify pad s) s := by
  simp [tune, ho]
  omega

/-- An overrun within the ceiling raises the pad. -/
theorem tune_strict (hi pad s : Nat) (hs : s ≤ hi) (ho : classify pad s = .over) :
    pad < tune true hi pad (classify pad s) s := by
  have h1 := tune_covers hi pad s hs ho
  have h2 := over_gt pad s ho
  omega

/-- The pad after the passes that spent each of `ss` in turn, and the count of the overruns among them. -/
def walk (hi : Nat) : Nat → List Nat → Nat × Nat
  | pad, [] => (pad, 0)
  | pad, s :: ss =>
    let next := walk hi (tune true hi pad (classify pad s) s) ss
    (next.1, next.2 + if classify pad s = .over then 1 else 0)

/-- Each overrun within the ceiling raises the pad by one tick at least, and the pad stays within the ceiling.
So the overruns are the rise of the pad at max. -/
theorem walk_overruns (hi : Nat) : ∀ (ss : List Nat) (pad : Nat), pad ≤ hi → (∀ s ∈ ss, s ≤ hi) →
    (walk hi pad ss).2 + pad ≤ (walk hi pad ss).1 ∧ (walk hi pad ss).1 ≤ hi := by
  intro ss
  induction ss with
  | nil => intro pad hp _; simp [walk]; exact hp
  | cons s ss ih =>
    intro pad hp hall
    have hs : s ≤ hi := hall s (List.mem_cons_self ..)
    have hrest : ∀ x ∈ ss, x ≤ hi := fun x hx => hall x (List.mem_cons_of_mem _ hx)
    have hmono := tune_mono true hi pad s hp
    have hle := tune_le true hi pad (classify pad s) s hp
    have ih' := ih (tune true hi pad (classify pad s) s) hle hrest
    simp only [walk]
    by_cases ho : classify pad s = .over
    · have hstrict := tune_strict hi pad s hs ho
      rw [ho] at hstrict ih'
      simp only [ho, ite_true]
      omega
    · simp only [ho, ite_false]
      omega

/-- Over the life of a slot, the overruns of bodies within the ceiling are `hi - pad` at max. -/
theorem overruns_bounded (hi pad : Nat) (ss : List Nat) (hp : pad ≤ hi) (hall : ∀ s ∈ ss, s ≤ hi) :
    (walk hi pad ss).2 ≤ hi - pad := by
  have := walk_overruns hi ss pad hp hall
  omega

end TimeDeterminism
