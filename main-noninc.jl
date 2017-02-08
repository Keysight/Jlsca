
using Sca
using Trs
using Align

import Sca.FORWARD,Sca.BACKWARD,Sca.PHASE1,Sca.PHASE2,Sca.PHASE3,Sca.PHASE4,Sca.PHASE5,Sca.PHASE6,Sca.SBOX,Sca.ROUNDOUT,Sca.TDES1,Sca.TDES2,Sca.TDES3

# our vanilla  main function
function go()
  if length(ARGS) < 1
    @printf("no input trace\n")
    return
  end

  if nworkers() > 1
    @printf("This module does not use parallelization!")
  end

  filename = ARGS[1]
  direction::Direction = (length(ARGS) > 1 && ARGS[2] == "BACKWARD" ? BACKWARD : FORWARD)
  params = getParameters(filename, direction)
  if params == nothing
    params = AesSboxAttack()
  end

  params.analysis.leakageFunctions = [hw]
  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  trs = InspectorTrace(filename)

  # # example alignment pass
  # maxShift = 20000
  # referenceOffset = 5000
  # reference = trs[1][2][referenceOffset:referenceOffset+5000]
  # corvalMin = 0.4
  # alignstate = CorrelationAlignFFT(reference, referenceOffset, maxShift)
  # addSamplePass(trs, x -> ((shift,corval) = correlationAlign(x, alignstate); corval > corvalMin ? circshift(x, shift) : Vector{eltype(x)}(0)))

  numberOfTraces = length(trs)

  ret = sca(trs, params, 1, numberOfTraces)

  return ret
end

@time go()
