
using Sca
using Trs
using Align

import Sca.FORWARD,Sca.BACKWARD,Sca.PHASE1,Sca.PHASE2,Sca.PHASE3,Sca.PHASE4,Sca.PHASE5,Sca.PHASE6,Sca.SBOX,Sca.ROUNDOUT,Sca.TDES1,Sca.TDES2,Sca.TDES3,Sca.CIPHER,Sca.INVCIPHER,Sca.EQINVCIPHER

function gf2dot(xx::Array{UInt8}, y::UInt8)
  return map(x -> gf2dot(x,y), xx)
end

function gf2dot(x::UInt8, y::UInt8)
  ret::UInt8 = 0

  for i in 0:7
    ret $= ((x >> i) & 1) & ((y >> i) & 1)
  end

  return ret
end

# uses the leakage models defined by Jakub Klemsa in his MSc thesis (see docs/Jakub_Klemsa---Diploma_Thesis.pdf) to attack Dual AES  implementations (see docs/dual aes.pdf)
function gofaster()
  if length(ARGS) < 1
    @printf("no input trace\n")
    return
  end

  filename = ARGS[1]

  # hardcoded for AES128 FORWARD.
  params = AesSboxAttack()
  params.mode = CIPHER
  params.direction = FORWARD
  params.dataOffset = 1
  params.analysis = DPA()
  params.analysis.statistic = cor
  params.analysis.leakageFunctions = [x -> gf2dot(x,UInt8(y)) for y in 1:255]
  # only a few key bytes at a time, since the large #leakageFunctions are requiring lots of memory
  params.keyByteOffsets = [1,4]

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  localtrs = InspectorTrace(filename, true)
  addSamplePass(localtrs, tobits)

  @everyworker begin
      using Trs
      # the "true" argument will force the sample type to be UInt64, throws an exception if samples are not 8-byte aligned
      trs = InspectorTrace($filename, true)

      # this efficiently converts UInt64 to packed BitVectors
      addSamplePass(trs, tobits)

      setPostProcessor(trs, CondReduce(SplitByData($numberOfAverages, $numberOfCandidates), $localtrs))
  end

  numberOfTraces = @fetch length(Main.trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
