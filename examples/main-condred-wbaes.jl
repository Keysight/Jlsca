
@everywhere using Jlsca.Sca
@everywhere using Jlsca.Trs
@everywhere using Jlsca.Align
@everywhere using Jlsca.Aes

import Jlsca.Sca.leak

# Leakage models defined by Jakub Klemsa in his MSc thesis (see
# docs/Jakub_Klemsa---Diploma_Thesis.pdf) to attack Dual AES # implementations
# (see docs/dual aes.pdf)
type Klemsa <: Leakage 
  y::UInt8
end
leak(a::Klemsa, x::UInt8) = gf2dot(x,a.y)

function gf2dot(x::UInt8, y::UInt8)
  ret::UInt8 = 0

  for i in 0:7
    ret ⊻= ((x >> i) & 1) & ((y >> i) & 1)
  end

  return ret
end

function gofaster()
  if length(ARGS) < 1
    @printf("no input trace\n")
    return
  end

  filename = ARGS[1]

  # hardcoded for AES128 FORWARD, but this works for any AES, any direction, any
  # round key.
  params = DpaAttack(AesSboxAttack(),CPA())
  params.attack.mode = CIPHER
  params.attack.keyLength = KL128
  params.attack.direction = FORWARD
  params.dataOffset = 1
  
  # the leakage function to attack dual AESes
  params.analysis.leakages = [Klemsa(y) for y in 1:255]
  
  # to get what's called AES INVMUL SBOX in Daredevil
  params.attack.sbox = map(Aes.gf8_inv, collect(UInt8, 0:255))

  params.targetOffsets = collect(1:16)
  params.phases = [PHASE1]

  toBitsEfficient = true

  @everywhere begin
      # the "true" argument will force the sample type to be UInt64, throws an exception if samples are not 8-byte aligned
      trs = InspectorTrace($filename, $toBitsEfficient)

      # this converts to packed BitVectors (efficiently, if toBitsEfficient is set)
      addSamplePass(trs, BitPass())

      setPostProcessor(trs, CondReduce(SplitByTracesBlock()))
  end

  numberOfTraces = length(trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
