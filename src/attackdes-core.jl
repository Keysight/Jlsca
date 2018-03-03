# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Des
using ..Trs

export DesSboxAttack

@enum DesMode DES=1 TDES1=2 TDES2=3 TDES3=4

for s in instances(DesMode); @eval export $(Symbol(s)); end

const left = 1:32
const right = 33:64

abstract type DesAttack <: Attack{UInt8} end

numberOfTargets(a::DesAttack, phase::Int) = 8

type DesSboxAttack <: DesAttack
  mode::DesMode
  encrypt::Bool
  direction::Direction
  xor::Bool

  function DesSboxAttack()
    return new(DES, true, FORWARD, false)
  end
end

type DesRoundAttack <: DesAttack
  mode::DesMode
  encrypt::Bool
  direction::Direction
  xor::Bool

  function DesRoundAttack()
    return new(DES, true, FORWARD, false)
  end
end

function numberOfPhases(params::DesAttack)
  if params.mode == DES || params.mode == TDES1
    return PHASE2
  elseif params.mode == TDES2
    return PHASE4
  elseif params.mode == TDES3
    return PHASE6
  end
end

show(io::IO, a::DesSboxAttack) = print(io, "DES Sbox")
show(io::IO, a::DesRoundAttack) = print(io, "DES Round")

function printParameters(params::DesAttack, attackStr::String)
  @printf("mode:         %s %s\n", string(params.mode), (params.encrypt ? "ENC" : "DEC"))
  @printf("direction:    %s\n", string(params.direction))
  @printf("xor:          %s\n", string(params.xor))
end

printParameters(params::DesSboxAttack) = printParameters(params, "Sbox")
printParameters(params::DesRoundAttack) = printParameters(params, "Round")

function getIdx(sixbits::Union{UInt16, UInt8})
  idx = (sixbits >> 5)
  idx = idx << 1
  idx = idx | (sixbits & 1)
  idx = idx << 4
  idx = idx | ((sixbits >> 1) & 0xf)
  return idx
end

const desguesses = collect(UInt8,0:63)

# target functions
type DesSboxOut <: Target{UInt8,UInt8,UInt8} 
  sbidx::Int
end

target(this::DesSboxOut, sixbits::Union{UInt16, UInt8}, kb::UInt8) = Sbox(this.sbidx)[getIdx((sixbits & 0x3f) ⊻ kb) + 1]
show(io::IO, a::DesSboxOut) = print(io, "Sbox $(a.sbidx) out")
guesses(a::DesSboxOut) = desguesses

type DesSboxOutXORin <: Target{UInt8,UInt8,UInt8}  end


function target(this::DesSboxOutXORin, sixbits::Union{UInt16, UInt8}, kb::UInt8)
  inp =  ((sixbits & 0x3f) ⊻ kb) & 0xf
  outp = Sbox(sbidx)[inp + 1]
  return inp .⊻ outp
end

show(io::IO, a::DesSboxOutXORin) = print(io, "Sbox $(a.sbidx) out XOR in")
guesses(a::DesSboxOutXORin) = desguesses

type RoundOut <: Target{UInt16,UInt16,UInt8} 
  sbidx::Int
end

target(this::RoundOut, tenbits::UInt16, kb::UInt8) = Sbox(this.sbidx)[getIdx((tenbits & 0x3f) ⊻ kb) + 1] ⊻ (tenbits >> 6)
show(io::IO, a::RoundOut) = print(io, "Round out, sbox $(a.sbidx)")
guesses(a::RoundOut) = desguesses

# round functions

# works on rows of data, returns either a vector of UInt8, or UInt16
function round1(input::Vector{UInt8}, params::DesSboxAttack)
  ip = IP(toBits(input[1:8]))
  invplefts = toNibbles(invP(ip[left]))

	sboxins = toSixbits(E(ip[right]))

  return sboxins
end

function round1(input::Vector{UInt8}, params::DesRoundAttack)
  ip = IP(toBits(input[1:8]))
  invplefts = toNibbles(invP(ip[left]))
  if params.xor
    # does the xor for roundOut with input (that's why there's no roundOutXORIn)
    invplefts .⊻= toNibbles(invP(ip[right]))
  end

  sboxins = toSixbits(E(ip[right]))

  return map((x,y) -> (UInt16(x) << 6) | y, invplefts, sboxins)
end

# works on rows of data, returns either a vector of UInt8, or UInt16
function round2(input::Vector{UInt8}, rk1::BitVector, params::DesSboxAttack)
  state = IP(toBits(input[1:8]))
  state[1:64] = [state[right]; f(state[right],rk1) .⊻ state[left]]

  sboxins = toSixbits(E(state[right]))

  return sboxins
end

function round2(input::Vector{UInt8}, rk1::BitVector, params::DesRoundAttack)
  state = IP(toBits(input[1:8]))
  state[1:64] = [state[right]; f(state[right],rk1) .⊻ state[left]]

  invplefts = toNibbles(invP(state[left]))
  if params.xor
    invplefts .⊻= toNibbles(invP(state[right]))
  end

  sboxins = toSixbits(E(state[right]))

  return map((x,y) -> (UInt16(x) << 6) | y, invplefts, sboxins)
end

function middleDesRound1(input::Vector{UInt8}, expDesKey::BitVector, encrypt::Bool, params::DesAttack)
  return round1(Des.Cipher(input[1:8], expDesKey, (x,y)->y, encrypt), params)
end

function middleDesRound2(input::Vector{UInt8}, expDesKey::BitVector, rk1::BitVector, encrypt::Bool, params::DesAttack)
  return round2(Des.Cipher(input[1:8], expDesKey, (x,y)->y, encrypt), rk1, params)
end

function innerDesRound1(input::Vector{UInt8}, expDesKey1::BitVector, expDesKey2::BitVector, encrypt::Bool, params::DesAttack)
  return round1(Des.Cipher(Des.Cipher(input[1:8], expDesKey1, (x,y)->y, encrypt), expDesKey2, (x,y)->y, !encrypt), params)
end

function innerDesRound2(input::Vector{UInt8}, expDesKey1::BitVector, expDesKey2::BitVector, rk1::BitVector, encrypt::Bool, params::DesAttack)
  return round2(Des.Cipher(Des.Cipher(input[1:8], expDesKey1, (x,y)->y, encrypt), expDesKey2, (x,y)->y, !encrypt), rk1, params)
end

function getTargets(params::DesSboxAttack, phase::Int, phaseInput::Vector{UInt8})
  if params.xor
    return [DesSboxOutXORin(sbidx) for sbidx in 1:8]
  else
    return [DesSboxOut(sbidx) for sbidx in 1:8]
  end
end

function getTargets(params::DesRoundAttack, phase::Int, phaseInput::Vector{UInt8})
  return [RoundOut(sbidx) for sbidx in 1:8]
end

function getDataPass(params::DesAttack, phase::Int, phaseInput::Vector{UInt8})
  if params.direction == BACKWARD
    encrypt = !params.encrypt
  else
    encrypt = params.encrypt
  end

  if phase == PHASE1
    roundfn = Nullable(x -> round1(x, params))
  elseif phase == PHASE2
    roundfn = Nullable(x -> round2(x, toBits(phaseInput, 6), params))
  elseif phase == PHASE3
    desKey = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
    expDesKey = Des.KeyExpansion(desKey)
    roundfn = Nullable(x -> middleDesRound1(x, expDesKey, encrypt, params))
  elseif phase == PHASE4
    desKey = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
    expDesKey = Des.KeyExpansion(desKey)
    roundKey = toBits(phaseInput[17:24], 6)
    roundfn = Nullable(x -> middleDesRound2(x, expDesKey, roundKey, encrypt, params))
  elseif phase == PHASE5
    desKey1 = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
    desKey2 = recoverKeyHelper(params, PHASE4, phaseInput[17:24], phaseInput[25:32])
    expDesKey1 = Des.KeyExpansion(desKey1)
    expDesKey2 = Des.KeyExpansion(desKey2)
    roundfn = Nullable(x -> innerDesRound1(x, expDesKey1, expDesKey2, encrypt, params))
  elseif phase == PHASE6
    desKey1 = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
    desKey2 = recoverKeyHelper(params, PHASE4, phaseInput[17:24], phaseInput[25:32])
    expDesKey1 = Des.KeyExpansion(desKey1)
    expDesKey2 = Des.KeyExpansion(desKey2)
    roundKey = toBits(phaseInput[33:40], 6)
    roundfn = Nullable(x -> innerDesRound2(x, expDesKey1, expDesKey2, roundKey, encrypt, params))
  end

  return roundfn

end

function recoverKeyHelper(params::DesAttack, phase::Int, rk1::Vector{UInt8}, rk2::Vector{UInt8})
  rk1bits = toBits(rk1, 6)
  rk2bits = toBits(rk2, 6)

  if phase == PHASE1 || phase == PHASE2
    encrypt = params.encrypt
  elseif phase == PHASE3 || phase == PHASE4
    encrypt = !params.encrypt
  elseif phase == PHASE5 || phase == PHASE6
    encrypt = params.encrypt
  end

  if (encrypt && params.direction == FORWARD) || (!encrypt && params.direction == BACKWARD)
    key = Des.KeyExpansionBackwards(rk1bits, 1, rk2bits, 2)
  else
    key = Des.KeyExpansionBackwards(rk1bits, 16, rk2bits, 15)
  end

  return key
end

function recoverKey(params::DesAttack, phaseInput::Vector{UInt8})
    if params.mode == DES || params.mode == TDES1
      key = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
    elseif params.mode == TDES2
      key1 = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
      key2 = recoverKeyHelper(params, PHASE4, phaseInput[17:24], phaseInput[25:32])
      key = vcat(key1,key2)
    else
      key1 = recoverKeyHelper(params, PHASE2, phaseInput[1:8], phaseInput[9:16])
      key2 = recoverKeyHelper(params, PHASE4, phaseInput[17:24], phaseInput[25:32])
      key3 = recoverKeyHelper(params, PHASE6, phaseInput[33:40], phaseInput[41:48])
      if (params.encrypt && params.direction == FORWARD) || (!params.encrypt && params.direction == BACKWARD)
        key = vcat(key1,key2,key3)
      else
        key = vcat(key3,key2,key1)
      end
    end

    return key
end

function correctKeyMaterial(params::DesAttack, knownKey::Vector{UInt8})
  rk = Vector{UInt8}(0)

  key1 = 1:8
  key2 = 9:16
  key3 = 17:24

  if params.mode == TDES3 && ((!params.encrypt && params.direction == FORWARD) || (params.encrypt && params.direction == BACKWARD))
    key3 = 1:8
    key2 = 9:16
    key1 = 17:24
  end

  for phase in 1:numberOfPhases(params)

    if phase == PHASE1 || phase == PHASE2
      key = knownKey[key1]
      encrypt = params.encrypt
    elseif phase == PHASE3 || phase == PHASE4
      key = knownKey[key2]
      encrypt = !params.encrypt
    elseif phase == PHASE5 || phase == PHASE6
      key = knownKey[key3]
      encrypt = params.encrypt
    end

    expKey = Des.KeyExpansion(key)

    mode = params.mode
    direction = params.direction

    if phase == PHASE1 || phase == PHASE3 || phase == PHASE5
      if (encrypt && direction == FORWARD) || (!encrypt && direction == BACKWARD)
        r = 1
      else
        r = 16
      end
    elseif phase == PHASE2 || phase == PHASE4 || phase == PHASE6
      if (encrypt && direction == FORWARD) || (!encrypt && direction == BACKWARD)
        r = 2
      else
        r = 15
      end
    end

    rk = vcat(rk, toSixbits(getK(expKey,r)))
  end

  return rk
end

# if two candidates are winning (within 5% margin), then don't consider the winner that equals the round key of the "other" DES
function pick(scorecol::Vector{Float64}, col::Int, block::UInt8)
  sorted = sortperm(scorecol, rev=true)

  maxval = max(scorecol[sorted[1]],scorecol[sorted[2]])
  minval = min(scorecol[sorted[1]],scorecol[sorted[2]])

  margin = maxval * .05
  if minval > (maxval - margin)
    if block == UInt8(sorted[1]-1)
      @printf("Discarding candidate 0x%02x of S-box %d\n", block, col)
      return UInt8(sorted[2]-1)
    else
      return UInt8(sorted[1]-1)
    end
  else
    return UInt8(sorted[1]-1)
  end
end

# a better way to get a round key from the scores
function getPhaseKey(a::DpaAttack, params::DesAttack, phase::Int, sc::RankData)
  if phase in [PHASE3;PHASE5]
    targets = getTargets(sc, phase)
    phaseOutput = a.phaseData
    o1 = offset(a,phase-2)
    o2 = offset(a,phase-1)
    wrongdeskey = recoverKeyHelper(params, phase-1, phaseOutput[o1+1:o1+8], phaseOutput[o2+1:o2+8])

    if params.direction == BACKWARD
      encrypt = !params.encrypt
    else
      encrypt = params.encrypt
    end

    expdes = Des.KeyExpansion(wrongdeskey)
    if (encrypt && phase == PHASE3) || (!encrypt && phase == PHASE5)
      wrongrk = toSixbits(getK(expdes, 16))
    else
      wrongrk = toSixbits(getK(expdes, 1))
    end


    rk = zeros(UInt8, length(targets))


    for c in 1:length(targets)
      combinedscores = getScores(sc,phase,targets[c])
      rk[c] = pick(combinedscores,targets[c],wrongrk[c])
    end

    return rk
  else
    return map(x -> UInt8(sortperm(getScores(sc,phase,x), rev=true)[1] - 1), getTargets(sc, phase))
  end
end

isKeyCorrect(a::DesAttack, key1::Vector{UInt8}, key2::Vector{UInt8}) = (key1 .& 0xfe) == (key2 .& 0xfe)
