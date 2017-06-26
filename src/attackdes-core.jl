# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

using ..Des
using ..Trs

export DesSboxAttack

@enum DesMode DES=1 TDES1=2 TDES2=3 TDES3=4
@enum DesTargetType SBOX=1 ROUNDOUT=2

for s in instances(DesMode); @eval export $(Symbol(s)); end
for s in instances(DesTargetType); @eval export $(Symbol(s)); end

const left = 1:32
const right = 33:64

abstract type DesAttack <: Attack end

nrKeyByteValues(a::DesAttack) = 64
keyByteValues(a::DesAttack) = collect(UInt8,0:63)

type DesSboxAttack <: DesAttack
  mode::DesMode
  encrypt::Bool
  direction::Direction
  dataOffset::Int
  keyByteOffsets::Vector{Int}
  knownKey::Nullable{Vector{UInt8}}
  analysis::Analysis
  updateInterval::Nullable{Int}
  targetType::DesTargetType
  xor::Bool
  phases::Vector{Phase}
  phaseInput::Nullable
  outputkka::Nullable{AbstractString}

  function DesSboxAttack()
    dpa = CPA()
    dpa.leakages = [Bit(0), Bit(1), Bit(2), Bit(3), Bit(4)]
    return new(DES, true, FORWARD, 1, collect(1:8), Nullable(), dpa, Nullable(), ROUNDOUT, false, [], Nullable(), Nullable())
  end
end

function getPhases(params::DesSboxAttack)
  if params.mode == DES || params.mode == TDES1
    return [PHASE1, PHASE2]
  elseif params.mode == TDES2
    return [PHASE1, PHASE2, PHASE3, PHASE4]
  elseif params.mode == TDES3
    return [PHASE1, PHASE2, PHASE3, PHASE4, PHASE5, PHASE6]
  end
end

function toShortString(params::DesSboxAttack)
  typeStr = (isa(params,DesSboxAttack) ? "SBOX" : "XXX")
  modeStr = string(params.mode)
  directionStr = string(params.direction)
  analysisStr = (isa(params.analysis, CPA) ? "CPA" : "LRA")

  return @sprintf("%s_%s_%s_%s", typeStr, modeStr, analysisStr, directionStr)
 end

function printParameters(params::DesSboxAttack)
  target = getTarget(params)

  attackStr = "Sbox"
  analysisStr = string(typeof(params.analysis).name.name)

  @printf("DES %s %s attack parameters\n", attackStr, analysisStr)
  printParameters(params.analysis)
  @printf("mode:       %s %s\n", string(params.mode), (params.encrypt ? "ENC" : "DEC"))
  @printf("direction:  %s\n", string(params.direction))
  @printf("target:     %s\n", string(target))
  @printf("xor:        %s\n", string(params.xor))
  @printf("data at:    %s\n", string(params.dataOffset))
  @printf("key bytes:  %s\n", string(params.keyByteOffsets))
  if !isnull(params.knownKey)
	 @printf("known key:  %s\n", bytes2hex(get(params.knownKey)))
  end
end

function getIdx(sixbits::Union{UInt16, UInt8})
  idx = (sixbits >> 5)
  idx = idx << 1
  idx = idx | (sixbits & 1)
  idx = idx << 4
  idx = idx | ((sixbits >> 1) & 0xf)
  return idx
end

# target functions
type DesSboxOut <: Target{UInt8,UInt8} end

target(this::DesSboxOut, sixbits::Union{UInt16, UInt8}, sbidx::Int, kb::UInt8) = Sbox(sbidx)[getIdx((sixbits & 0x3f) ⊻ kb) + 1]

type DesSboxOutXORin <: Target{UInt8,UInt8} end

function target(this::DesSboxOutXORin, sixbits::Union{UInt16, UInt8}, sbidx::Int, kb::UInt8)
  inp =  ((sixbits & 0x3f) ⊻ kb) & 0xf
  outp = Sbox(sbidx)[inp + 1]
  return inp ⊻ outp
end

type RoundOut <: Target{UInt16,UInt16} end

target(this::RoundOut, tenbits::UInt16, sbidx::Int, kb::UInt8) = Sbox(sbidx)[getIdx((tenbits & 0x3f) ⊻ kb) + 1] ⊻ (tenbits >> 6)

# round functions

# works on rows of data, returns either a vector of UInt8, or UInt16
function round1(input::Vector{UInt8}, params::DesSboxAttack)
  ip = IP(toBits(input))
  invplefts = toNibbles(invP(ip[left]))[params.keyByteOffsets]
  if params.targetType == ROUNDOUT
    if params.xor
      # does the xor for roundOut with input (that's why there's no roundOutXORIn)
      invplefts $= toNibbles(invP(ip[right]))[params.keyByteOffsets]
    end
  end

	sboxins = toSixbits(E(ip[right]))[params.keyByteOffsets]

  if params.targetType == ROUNDOUT
    return map((x,y) -> (UInt16(x) << 6) | y, invplefts, sboxins)
  else
    return sboxins
  end
end

# works on rows of data, returns either a vector of UInt8, or UInt16
function round2(input::Vector{UInt8}, rk1::BitVector, params::DesSboxAttack)
  state = IP(toBits(input))
  state[1:64] = [state[right]; f(state[right],rk1) .⊻ state[left]]

  if params.targetType == ROUNDOUT
    invplefts = toNibbles(invP(state[left]))[params.keyByteOffsets]
    if params.xor
      invplefts $= toNibbles(invP(state[right]))[params.keyByteOffsets]
    end
  end

  sboxins = toSixbits(E(state[right]))[params.keyByteOffsets]

  if params.targetType == ROUNDOUT
    return map((x,y) -> (UInt16(x) << 6) | y, invplefts, sboxins)
  else
    return sboxins
  end
end

function middleDesRound1(input::Vector{UInt8}, expDesKey::BitVector, encrypt::Bool, params::DesSboxAttack)
  return round1(Des.Cipher(input, expDesKey, (x,y)->y, encrypt), params)
end

function middleDesRound2(input::Vector{UInt8}, expDesKey::BitVector, rk1::BitVector, encrypt::Bool, params::DesSboxAttack)
  return round2(Des.Cipher(input, expDesKey, (x,y)->y, encrypt), rk1, params)
end

function innerDesRound1(input::Vector{UInt8}, expDesKey1::BitVector, expDesKey2::BitVector, encrypt::Bool, params::DesSboxAttack)
  return round1(Des.Cipher(Des.Cipher(input, expDesKey1, (x,y)->y, encrypt), expDesKey2, (x,y)->y, !encrypt), params)
end

function innerDesRound2(input::Vector{UInt8}, expDesKey1::BitVector, expDesKey2::BitVector, rk1::BitVector, encrypt::Bool, params::DesSboxAttack)
  return round2(Des.Cipher(Des.Cipher(input, expDesKey1, (x,y)->y, encrypt), expDesKey2, (x,y)->y, !encrypt), rk1, params)
end

function getNumberOfCandidates(params::DesSboxAttack)
  if params.targetType == ROUNDOUT
    return 1024
  else
    return 64
  end
end

function getTarget(params::DesSboxAttack)
  if params.targetType == ROUNDOUT
  	return RoundOut()
  else
    if params.xor
      return DesSboxOutXORin()
    else
      return DesSboxOut()
    end
  end
end

function getRoundFunction(phase::Phase, params::DesSboxAttack, phaseInput=Nullable())
  if params.direction == BACKWARD
    encrypt = !params.encrypt
  else
    encrypt = params.encrypt
  end

  if phase == PHASE1
    roundfn = Nullable(x -> round1(x, params))
  elseif phase == PHASE2
    roundfn = Nullable(x -> round2(x, toBits(get(phaseInput), 6), params))
  elseif phase == PHASE3
    expDesKey = Des.KeyExpansion(get(phaseInput))
    roundfn = Nullable(x -> middleDesRound1(x, expDesKey, encrypt, params))
  elseif phase == PHASE4
    expDesKey = Des.KeyExpansion(get(phaseInput)[1:8])
    roundKey = toBits(get(phaseInput)[9:16], 6)
    roundfn = Nullable(x -> middleDesRound2(x, expDesKey, roundKey, encrypt, params))
  elseif phase == PHASE5
    expDesKey1 = Des.KeyExpansion(get(phaseInput)[1:8])
    expDesKey2 = Des.KeyExpansion(get(phaseInput)[9:16])
    roundfn = Nullable(x -> innerDesRound1(x, expDesKey1, expDesKey2, encrypt, params))
  elseif phase == PHASE6
    expDesKey1 = Des.KeyExpansion(get(phaseInput)[1:8])
    expDesKey2 = Des.KeyExpansion(get(phaseInput)[9:16])
    roundKey = toBits(get(phaseInput)[17:24], 6)
    roundfn = Nullable(x -> innerDesRound2(x, expDesKey1, expDesKey2, roundKey, encrypt, params))
  end

  return roundfn

end

function recoverKey(params::DesSboxAttack, phase::Phase, rk1::Vector{UInt8}, rk2::Vector{UInt8})
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

function getCorrectRoundKeyMaterial(params::DesSboxAttack, phase::Phase)
	if isnull(params.knownKey)
	    return Nullable{Vector{UInt8}}()
	end

  key1 = 1:8
  key2 = 9:16
  key3 = 17:24

  if params.mode == TDES3 && ((!params.encrypt && params.direction == FORWARD) || (params.encrypt && params.direction == BACKWARD))
    key3 = 1:8
    key2 = 9:16
    key1 = 17:24
  end

  if phase == PHASE1 || phase == PHASE2
    key = get(params.knownKey)[key1]
    encrypt = params.encrypt
  elseif phase == PHASE3 || phase == PHASE4
    key = get(params.knownKey)[key2]
    encrypt = !params.encrypt
  elseif phase == PHASE5 || phase == PHASE6
    key = get(params.knownKey)[key3]
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

	return Nullable(toSixbits(getK(expKey,r)))

end

function scatask(super::Task, trs::Trace, params::DesSboxAttack, firstTrace=1, numberOfTraces=length(trs), phase::Phase=PHASE1, phaseInput=params.phaseInput)

  target = getTarget(params)

  local key, scores

  addDataPass(trs, (x -> x[params.dataOffset + collect(0:7)]))

  roundfn = getRoundFunction(phase, params, phaseInput)

	# if we have a round function, add it
  if !isnull(roundfn)
    addDataPass(trs, get(roundfn))
  end

  # do the attack
  scores = analysis(super, params, phase, trs, firstTrace, numberOfTraces, target, params.keyByteOffsets)

  # if we added a round function on the input data, now we need to remove it
  if !isnull(roundfn)
    popDataPass(trs)
  end

  popDataPass(trs)

  if length(params.keyByteOffsets) < 8
    yieldto(super, (FINISHED, nothing))
    return
  end

  # get the recovered key material & be done with it
  if phase in [PHASE3;PHASE5]
    # kill the candidates that light up in DES1R16 when attacking DES2R1, etc..
    roundkey_ = getRoundKey(scores)
    roundkey = getRoundKeyBetter(params, phase, scores, get(phaseInput)[end-7:end])
    if roundkey_ != roundkey
      @printf("Corrected round key: %s\n", bytes2hex(roundkey))
    end
  else
    roundkey = getRoundKey(scores)
  end

  # we're not done: determine what more to do
  if phase == PHASE1
    # produce a roundkey
    yieldto(super, (PHASERESULT, Nullable(roundkey)))
  elseif phase == PHASE2
    # produce key
    key = recoverKey(params, phase, get(phaseInput), roundkey)
    if params.mode == DES || params.mode == TDES1
      yieldto(super, (FINISHED, key))
    else
      yieldto(super, (PHASERESULT, Nullable(key)))
    end
  elseif phase == PHASE3
    # produce key + roundkey
    yieldto(super, (PHASERESULT, Nullable([get(phaseInput);roundkey])))
  elseif phase == PHASE4
    # produce key + key
    key = recoverKey(params, phase, get(phaseInput)[end-7:end], roundkey)
    nextPhaseInput = [get(phaseInput)[1:end-8]; key]
    if params.mode == TDES2
      yieldto(super, (FINISHED, nextPhaseInput))
    else
      yieldto(super, (PHASERESULT, Nullable(nextPhaseInput)))
    end
  elseif phase == PHASE5
    # produce key + key + roundkey
    yieldto(super, (PHASERESULT, Nullable([get(phaseInput);roundkey])))
  elseif phase == PHASE6
    # produce key + key + key
    key = recoverKey(params, phase, get(phaseInput)[end-7:end], roundkey)
    if (params.encrypt && params.direction == FORWARD) || (!params.encrypt && params.direction == BACKWARD)
      yieldto(super, (FINISHED, [get(phaseInput)[1:end-8]; key]))
    else
      yieldto(super, (FINISHED, [key;get(phaseInput)[9:16];get(phaseInput)[1:8]]))
    end
  end
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
function getRoundKeyBetter(params::DesSboxAttack, phase::Phase, scores::Matrix{Float64}, wrongdeskey::Vector{UInt8})
  rows,cols = size(scores)

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


  rk = zeros(UInt8, cols)

  for c in 1:cols
    rk[c] = pick(scores[:,c],c,wrongrk[c])
  end

  return rk
end
