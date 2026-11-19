import TimeDeterminism.Reading
import Std.Tactic.BVDecide

/-!
# TimeDeterminism, the words of the C

The C keeps a pad in one `uint32_t`: the pad in the low thirty bits and the last state in the top two. It
tunes the pad with masks and no branch. This file proves the masks on `BitVec 32`, bit for bit.

`cover` is the smaller of the ticks spent and the ceiling. `next` adds the rise from the pad to `cover` where
the pass overran, and adds nothing where it did not. From a pad within the ceiling, `next` is `tune`.
-/

namespace TimeDeterminism

/-- The bits of the pad, `IDEMIP_CLOCK_PAD_MASK`. -/
def padMask : BitVec 32 := 0x3FFFFFFF#32

/-- The shift of the state, `IDEMIP_CLOCK_PAD_SHIFT`. -/
def stateShift : Nat := 30

/-- The pad and the state fill the word, and no bit is in both. -/
theorem word_fills :
    padMask &&& (3#32 <<< stateShift) = 0#32 ∧ padMask ||| (3#32 <<< stateShift) = 0xFFFFFFFF#32 := by
  decide

/-- A word packed from a state and a pad gives the pad back. -/
theorem unpack_pad (st pad : BitVec 32) :
    (((st &&& 3#32) <<< 30) ||| (pad &&& padMask)) &&& padMask = pad &&& padMask := by
  simp only [padMask]
  bv_decide

/-- A word packed from a state and a pad gives the state back. -/
theorem unpack_state (st pad : BitVec 32) :
    ((((st &&& 3#32) <<< 30) ||| (pad &&& padMask)) >>> 30) &&& 3#32 = st &&& 3#32 := by
  simp only [padMask]
  bv_decide

/-- The mask of a flag: every bit set where the flag is set, none where it is clear. `0u - flag` in C. -/
def maskOf (flag : Bool) : BitVec 32 := 0#32 - (BitVec.ofBool flag).zeroExtend 32

/-- The smaller of the ticks spent and the ceiling, as the C takes it with no branch. -/
def cover (hi s : BitVec 32) : BitVec 32 := hi ^^^ ((s ^^^ hi) &&& maskOf (s.ult hi))

/-- The next pad, as the C takes it with no branch. `over` is set where the pass overran and the grade walks. -/
def next (hi pad s : BitVec 32) (over : Bool) : BitVec 32 := pad + ((cover hi s - pad) &&& maskOf over)

/-- `cover` is the smaller of the two. -/
theorem cover_min (hi s : BitVec 32) : cover hi s = if s.ult hi then s else hi := by
  unfold cover maskOf
  by_cases h : s.ult hi <;> simp [h] <;> bv_decide

/-- A pass that did not overrun leaves the pad as it is. -/
theorem next_same (hi pad s : BitVec 32) : next hi pad s false = pad := by
  unfold next maskOf
  simp

/-- An overrun from a pad within the ceiling gives the smaller of the ticks spent and the ceiling. -/
theorem next_over (hi pad s : BitVec 32) (hh : pad.ule hi) (ho : pad.ult s) :
    next hi pad s true = if s.ult hi then s else hi := by
  unfold next
  rw [← cover_min]
  unfold maskOf cover maskOf
  simp only [BitVec.ofBool_true]
  bv_decide

end TimeDeterminism
