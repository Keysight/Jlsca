
using Test
using Jlsca.Trs
using Random
using Printf

function createTmpFile(tail)
  return @sprintf("/tmp/tmp%s%s", String([UInt8(rand(0x30:0x5a)) for i in 1:10]), tail)
end

function testInspectorTrace()
  dataSpace = 7
  sampleType = Int16
  numberOfSamplesPerTrace = 29
  numberOfTitlebytes = 31
  numberOfTraces = 11
  traceFilename = createTmpFile("bob.trs")

  allTitles = rand(UInt8, (numberOfTraces, numberOfTitlebytes))
  allSamples = reshape([rand(Int16) for i in 1:(numberOfSamplesPerTrace*numberOfTraces)], (numberOfTraces,  numberOfSamplesPerTrace))
  allData = reshape([rand(UInt8) for i in 1:(dataSpace*numberOfTraces)], (numberOfTraces, dataSpace))

  trs = InspectorTrace(traceFilename, dataSpace, sampleType, numberOfSamplesPerTrace, titleSpace=numberOfTitlebytes)

  for i in randperm(numberOfTraces)
    trs[i] = (allData[i,:], allSamples[i,:])
    writeTitle(trs, i, allTitles[i,:])
    t = trs[i]
    @test (t.data,t.samples) == (allData[i,:], allSamples[i,:])
  end

  close(trs)

  trs2 = InspectorTrace(traceFilename)

  @test length(trs2) == numberOfTraces
  @test numberOfTitlebytes == trs2.titleSpace

  for i in randperm(numberOfTraces)
    t = trs2[i]
    @test (t.data,t.samples) == (allData[i,:], allSamples[i,:])
    @test readTitle(trs2,i) == allTitles[i,:]
  end

  close(trs2)

  rm(traceFilename)
end

function testInspectorTraceRanges()
  dataSpace = 9
  sampleType = UInt8
  numberOfSamplesPerTrace = 290
  numberOfTitlebytes = 31
  numberOfTraces = 110
  traceFilename = createTmpFile("bob.trs")

  allTitles = rand(UInt8, (numberOfTraces, numberOfTitlebytes))
  allSamples = reshape([rand(sampleType) for i in 1:(numberOfSamplesPerTrace*numberOfTraces)], (numberOfTraces,  numberOfSamplesPerTrace))
  allData = reshape([rand(UInt8) for i in 1:(dataSpace*numberOfTraces)], (numberOfTraces, dataSpace))

  trs = InspectorTrace(traceFilename, dataSpace, sampleType, numberOfSamplesPerTrace; titleSpace=numberOfTitlebytes)

  for i in randperm(numberOfTraces)
    trs[i] = (allData[i,:], allSamples[i,:])
    writeTitle(trs, i, allTitles[i,:])
    t = trs[i]
    @test (t.data,t.samples) == (allData[i,:], allSamples[i,:])
  end

  close(trs)

  trs2 = InspectorTrace(traceFilename)

  @test length(trs2) == numberOfTraces
  @test numberOfTitlebytes == trs2.titleSpace

  for i in randperm(numberOfTraces  )
    for r in 1:30:numberOfSamplesPerTrace
      e = min(numberOfSamplesPerTrace,r+30-1)
      @test Trs.readSamples(trs2, i, r:e) == allSamples[i,r:e]
    end
  end

  close(trs2)

  rm(traceFilename)
end


function testSplitBinary()
  dataSpace = 7
  sampleType = Float64
  numberOfSamplesPerTrace = 29
  numberOfTraces = 11
  samplesFilename = createTmpFile(@sprintf("_%s_%dt.bin", sampleType, numberOfTraces))
  dataFilename = createTmpFile(@sprintf("_UInt8_%dt.bin", numberOfTraces))

  allSamples = reshape([rand(sampleType) for i in 1:(numberOfSamplesPerTrace*numberOfTraces)], (numberOfTraces,  numberOfSamplesPerTrace))
  allData = reshape([rand(UInt8) for i in 1:(dataSpace*numberOfTraces)], (numberOfTraces, dataSpace))

  trs = SplitBinary(dataFilename, dataSpace, samplesFilename, numberOfSamplesPerTrace, sampleType, numberOfTraces, true)

  for i in 1:numberOfTraces
    trs[i] = (allData[i,:], allSamples[i,:])
    t = trs[i]
    @test (t.data,t.samples) == (allData[i,:], allSamples[i,:])
  end

  close(trs)

  trs2 = SplitBinary(dataFilename, samplesFilename)

  @test length(trs2) == numberOfTraces

  for i in 1:numberOfTraces
    t = trs2[i]
    @test (t.data,t.samples) == (allData[i,:], allSamples[i,:])
  end

  close(trs2)

  rm(samplesFilename)
  rm(dataFilename)
end


testInspectorTrace()
testInspectorTraceRanges()
testSplitBinary()
