# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export SplitBinary,readTrace,parseSamplesFilename

# split binary has the data and samples in different files, similar to how Daredevil reads its data. Since there is not metadata in these files, the meta data is encoded in and read from the file names.
type SplitBinary <: Trace
  numberOfTraces::Nullable{Int}
  dataSpace
  sampleType
  numberOfSamplesPerTrace
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

  function SplitBinary(dataFname, samplesFn)
    (numberOfSamplesPerTrace, sampleType, numberOfTraces1) = parseSamplesFilename(samplesFn)
    (dataSpace, dataType, numberOfTraces2) = parseDataFilename(dataFname)
    if numberOfTraces1 != numberOfTraces2
      throw(ErrorException())
    end
    SplitBinary(dataFname, dataSpace, samplesFn, numberOfSamplesPerTrace, sampleType, numberOfTraces1)
  end

  function SplitBinary(dataFname, dataSpace, samplesFn, numberOfSamplesPerTrace, sampleType, nrtraces)
    numberOfTraces = Nullable(nrtraces)
    # sampleType = UInt8
    samplesFileDescriptor = open(samplesFn, "r")
    dataFileDescriptor = open(dataFname, "r")
    new(numberOfTraces, dataSpace, sampleType, numberOfSamplesPerTrace, samplesFileDescriptor, dataFileDescriptor, [], [], Union, nothing, Union, Union, 0, 0)
  end
end

# don't support reading stuff from pipes, since then there is no file name and no meta data and it's a pain.
pipe(trs::SplitBinary) = false

length(trs::SplitBinary) = isnull(trs.numberOfTraces) ? typemax(Int) : get(trs.numberOfTraces)

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
      throw(EOFError())
    end

    if sampleType != UInt8
      trace = reinterpret(sampleType, trace)
      if ltoh(ENDIAN_BOM) != ENDIAN_BOM
        trace = map(ltoh, trace)
      end
    end

    # @printf("data: %s\n", bytes2hex(data))
    # @printf("samples: %s\n", bytes2hex(trace))
    # @printf("length(data) %d, length(samples) %d\n", length(data), length(trace))

    return (data, trace)
end

# parses #samples, type of samples, #traces from a file name (for example samples_1792_b_500.bin)
function parseSamplesFilename(fname::String)
  m = match(r"_([0-9]+)_([bfsi]{1})_([0-9]+)", fname)
  if m != nothing
    if m[2] == "f"
      t = Float32
    elseif m[2] == "b"
      t = UInt8
    elseif m[3] == "s"
      t = UInt16
    elseif m[4] == "i"
      t = UInt32
    end
    return (parse(m[1]), t, parse(m[3]))
  end
end

# parses #data elements, type of data elements, #traces from a file name (for example data_32_b_500.bin)
function parseDataFilename(fname::String)
  m = match(r"_([0-9]+)_([bfsi]{1})_([0-9]+)", fname)
  if m != nothing
    if m[2] == "b"
      t = UInt8
    elseif m[3] == "s"
      t = UInt16
    end
    return (parse(m[1]), t, parse(m[3]))
  end
end
