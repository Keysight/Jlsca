# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export SplitBinary,readTrace,parseSamplesFilename

# split binary has the data and samples in 2 different files, similar to how Daredevil reads its data and samples. Since there is not metadata in these files, the meta data is encoded in and read from the file names.
type SplitBinary <: Trace
  numberOfTraces::Int
  dataSpace::Int
  sampleType::Type
  numberOfSamplesPerTrace::Int
  samplesFileDescriptor
  dataFileDescriptor
  passes
  dataPasses
  postProcType
  postProcArguments
  postProcInstance
  bgtask
  tracesReturned
  prevIdx

  function SplitBinary(dataFn, samplesFn)
    (sampleSpace, sampleType, numberOfTracesSamples) = parseFilename(samplesFn)
    (dataSpace, dataType, numberOfTracesData) = parseFilename(dataFn)
    if isnull(sampleSpace) && isnull(numberOfTracesSamples) == nothing
      throw(ErrorException(@sprintf("Need either number of samples or number of traces in file name %s", samplesFn)))
    end
    if isnull(dataSpace) && isnull(numberOfTracesData)
      throw(ErrorException(@sprintf("Need either number of data samples or number of traces in file name %s", dataFn)))
    end
    samplesFileDescriptor = open(samplesFn, "r")
    bytesInSamplesFile = stat(samplesFileDescriptor).size
    close(samplesFileDescriptor)

    dataFileDescriptor = open(dataFn, "r")
    bytesInDataFile = stat(dataFileDescriptor).size
    close(dataFileDescriptor)

    if dataType != UInt8
      throw(ErrorException("Only UInt8 support for data"))
    end

    if !isnull(sampleSpace) &&  !isnull(numberOfTracesSamples)
      (bytesInSamplesFile >= get(sampleSpace) * sizeof(sampleType)) || throw(ErrorException("Sample file too small"))
    end

    if isnull(sampleSpace)
      sampleSpace = Nullable(div(div(bytesInSamplesFile, get(numberOfTracesSamples)), sizeof(sampleType)))
    end

    if isnull(numberOfTracesSamples)
      numberOfTracesSamples = Nullable(div(bytesInSamplesFile, get(sampleSpace) * sizeof(sampleType)))
    end

    if isnull(dataSpace)
      dataSpace = Nullable(div(div(bytesInDataFile, get(numberOfTracesData)), sizeof(dataType)))
    end

    if isnull(numberOfTracesData)
      numberOfTracesData = Nullable(div(div(bytesInDataFile, get(dataSpace)), sizeof(dataType)))
    end

    if get(numberOfTracesSamples) != get(numberOfTracesData)
      throw(ErrorException(@sprintf("Different #traces in samples %d versus data %d", get(numberOfTracesSamples), get(numberOfTracesData))))
    end

    SplitBinary(dataFn, get(dataSpace), samplesFn::String, get(sampleSpace), sampleType, get(numberOfTracesSamples))
  end

  function SplitBinary(dataFname::String, dataSpace::Int, samplesFn::String, numberOfSamplesPerTrace, sampleType, nrtraces)
    samplesFileDescriptor = open(samplesFn, "r")
    dataFileDescriptor = open(dataFname, "r")

    new(nrtraces, dataSpace, sampleType, numberOfSamplesPerTrace, samplesFileDescriptor, dataFileDescriptor, [], [], Union, nothing, Union, Union, 0, 0)
  end
end

pipe(trs::SplitBinary) = false

length(trs::SplitBinary) = trs.numberOfTraces

# read a single trace from the data and samples files
function readTrace(trs::SplitBinary, idx)
    # @printf("reading idx %d\n", idx)
    sf = trs.samplesFileDescriptor
    df = trs.dataFileDescriptor
    dataSpace = trs.dataSpace
    numberOfSamplesPerTrace = trs.numberOfSamplesPerTrace
    sampleType = trs.sampleType

    (data, trace) = (nothing, nothing)

    if !(trs.prevIdx + 1 == idx)
      # this is going to throw an exception when reading from stdin
      seek(sf, (idx-1) * (numberOfSamplesPerTrace * sizeof(sampleType)))
      seek(df, (idx-1) * (dataSpace))
    end

    trace = read(sf, numberOfSamplesPerTrace * sizeof(sampleType))
    data = read(df, dataSpace)

    trs.prevIdx = idx

    if length(data) == 0 && length(trace) == 0
      # @printf("wuuuut!\n")
      throw(EOFError())
    end

    if sampleType != UInt8
      trace = reinterpret(sampleType, trace)
      if ltoh(ENDIAN_BOM) != ENDIAN_BOM
        trace = map(ltoh, trace)
      end
    end

    # @printf("length(data) %d, length(samples) %d\n", length(data), length(trace))

    return (data, trace)
end

# parses #samples, type of samples, #traces from a file name (for example samples_Float64_64s_55t.bin, samples_Float64_64s.bin, samples_Float64_32t.bin)
function parseFilename(fname::String)
  regex = r"(Int64|UInt64|Int32|UInt32|Float64|Float32|Int16|UInt16|Int8|UInt8)?(_[0-9]+s)?(_[0-9]+t)?\.bin"
  m = match(regex, fname)
  if m != nothing
    myType_s,numberOfSamplesPerTrace_s,numberOfTraces_s = m.captures
    if numberOfSamplesPerTrace_s != nothing
      numberOfSamples = Nullable(parse(numberOfSamplesPerTrace_s[2:end-1]))
    else
      numberOfSamples = Nullable{Int}()
    end
    if numberOfTraces_s != nothing
      numberOfTraces = Nullable(parse(numberOfTraces_s[2:end-1]))
    else
      numberOfTraces = Nullable{Int}()
    end
    if myType_s != nothing
      myType =  eval(parse(myType_s))
    else
      myType = UInt8
    end
  else
    throw(ErrorException(@sprintf("File name %s doesn't match %s", fname, regex)))
  end

  return numberOfSamples,myType,numberOfTraces
end
