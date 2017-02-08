
using Sca
using Trs
using Align

import Sca.FORWARD,Sca.BACKWARD,Sca.PHASE1,Sca.PHASE2,Sca.PHASE3,Sca.PHASE4,Sca.PHASE5,Sca.PHASE6,Sca.SBOX,Sca.ROUNDOUT,Sca.TDES1,Sca.TDES2,Sca.TDES3

# our vanilla  main function
function gofaster()
  if length(ARGS) < 1
    @printf("no input trace\n")
    return
  end

  filename = ARGS[1]
  direction::Direction = (length(ARGS) > 1 && ARGS[2] == "BACKWARD" ? BACKWARD : FORWARD)
  params = getParameters(filename, direction)
  if params == nothing
    params = AesSboxAttack()
  end

  params.analysis = IncrementalCPA()
  params.analysis.leakageFunctions = [hw]

  numberOfAverages = length(params.keyByteOffsets)
  numberOfCandidates = getNumberOfCandidates(params)

  @everyworker begin
      using Trs
      using Align

      trs = InspectorTrace($filename)

      # # example alignment pass
      # maxShift = 20000
      # referenceOffset = 5000
      # reference = trs[1][2][referenceOffset:referenceOffset+5000]
      # corvalMin = 0.4
      # alignstate = CorrelationAlignFFT(reference, referenceOffset, maxShift)
      # addSamplePass(trs, x -> ((shift,corval) = correlationAlign(x, alignstate); corval > corvalMin ? circshift(x, shift) : Vector{eltype(x)}(0)))

      setPostProcessor(trs, IncrementalCorrelation(SplitByData($numberOfAverages, $numberOfCandidates)))
      # setPostProcessor(trs, IncrementalCorrelation(SplitByTracesBlock()))
      # setPostProcessor(trs, IncrementalCorrelation(SplitByTracesSliced()))
  end

  numberOfTraces = @fetch length(Main.trs)

  ret = sca(DistributedTrace(), params, 1, numberOfTraces)

  return ret
end

@time gofaster()
