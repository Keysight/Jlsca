
using Jlsca.Sca
using Jlsca.Trs
using Jlsca.Align
using Jlsca.Aes

gf2dot(xx::Array{UInt8}, y::UInt8) = map(x -> gf2dot(x,y), xx)

# Uses the leakage models defined by Jakub Klemsa in his MSc thesis (see
# docs/Jakub_Klemsa---Diploma_Thesis.pdf) to attack Dual AES # implementations
# (see docs/dual aes.pdf)
function gf2dot(x::UInt8, y::UInt8)
  ret::UInt8 = 0

  for i in 0:7
    ret $= ((x >> i) & 1) & ((y >> i) & 1)
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
  params = AesSboxAttack()
  params.mode = CIPHER
  params.keyLength = KL128
  params.direction = FORWARD
  params.dataOffset = 1
  params.analysis = DPA()
  params.analysis.statistic = cor
  
  # the leakage function to attack dual AESes
  params.analysis.leakageFunctions = [x -> gf2dot(x,UInt8(y)) for y in 1:255]
  
  # to get what's called AES INVMUL SBOX in Daredevil
  params.sbox = map(Aes.gf8_inv, collect(UInt8, 0:255))

  params.keyByteOffsets = collect(1:16)
  params.phases = [PHASE1]

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  toBitsEfficient = true

  localtrs = InspectorTrace(filename, toBitsEfficient)
  addSamplePass(localtrs, tobits)

  @everyworker begin
      using Jlsca.Trs
      # the "true" argument will force the sample type to be UInt64, throws an exception if samples are not 8-byte aligned
      trs = InspectorTrace($filename, $toBitsEfficient)

      # this converts to packed BitVectors (efficiently, if toBitsEfficient is set)
      addSamplePass(trs, tobits)

      setPostProcessor(trs, CondReduce(SplitByData($numberOfAverages, $numberOfCandidates), $localtrs))
  end

  numberOfTraces = @fetch length(Main.trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
