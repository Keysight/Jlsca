# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export SplitBinary

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
  postProcInstance
  bgtask
  tracesReturned
  samplesPosition
  dataPosition
  colRange::Nullable{Range}
  preColRange::Nullable{Range}
  viewsdirty::Bool
  views::Vector{Nullable{Range}}


  function SplitBinary(dataFn, samplesFn, bits::Bool = false)
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

    SplitBinary(dataFn, get(dataSpace), samplesFn::String, get(sampleSpace), sampleType, get(numberOfTracesSamples), false, bits)
  end

  function SplitBinary(dataFname::String, dataSpace::Int, samplesFn::String, numberOfSamplesPerTrace, sampleType, nrtraces, write::Bool=false, bits::Bool=false)
    samplesFileDescriptor = open(samplesFn, write ? "w+" : "r")
    dataFileDescriptor = open(dataFname, write ? "w+" :"r")


    if bits
      if (numberOfSamplesPerTrace * sizeof(sampleType)) % 8 != 0
        throw(ErrorException("samples needs to be 8 byte aligned in order to force sample type to UInt64!!!1\n"))
      end
      numberOfSamplesPerTrace = div((numberOfSamplesPerTrace * sizeof(sampleType)), 8)
      sampleType = UInt64
    end

    new(nrtraces, dataSpace, sampleType, numberOfSamplesPerTrace, samplesFileDescriptor, dataFileDescriptor, [], [], Union, Union, 0, 0, 0,Nullable{Range}(),Nullable{Range}(),true)
  end
end

pipe(trs::SplitBinary) = false

length(trs::SplitBinary) = trs.numberOfTraces

function readData(trs::SplitBinary, idx)
  if position(trs.dataFileDescriptor) != (idx-1) * trs.dataSpace
    seek(trs.dataFileDescriptor, (idx-1) * trs.dataSpace)
  end

  return read(trs.dataFileDescriptor, trs.dataSpace)
end

function writeData(trs::SplitBinary, idx, data::Vector{UInt8})
  trs.dataSpace == length(data) || throw(ErrorException(@sprintf("wrong data length %d, expecting %d", length(data), trs.dataSpace)))

  if position(trs.dataFileDescriptor) != (idx-1) * trs.dataSpace
    seek(trs.dataFileDescriptor, (idx-1) * trs.dataSpace)
  end

  write(trs.dataFileDescriptor, data)
end

readSamples(trs::SplitBinary, idx::Int) = readSamples(trs, idx, 1:trs.numberOfSamplesPerTrace)

function readSamples(trs::SplitBinary, idx, r::Range)
  issubset(r,1:trs.numberOfSamplesPerTrace) || error("requested range $r not in trs sample space $(1:trs.numberOfSamplesPerTrace)")
  bytesinsamples = trs.numberOfSamplesPerTrace * sizeof(trs.sampleType)
  pos = (idx-1) * bytesinsamples
  pos += (r[1]-1) * sizeof(trs.sampleType)

  if position(trs.samplesFileDescriptor) != pos
    seek(trs.samplesFileDescriptor, pos)
  end

  samples = read(trs.samplesFileDescriptor, trs.sampleType, length(r))

  if trs.sampleType != UInt8
    if ltoh(ENDIAN_BOM) != ENDIAN_BOM
      samples = map(ltoh, samples)
    end
  end

  return samples
end

function writeSamples(trs::SplitBinary, idx::Int, samples::Vector)
  trs.numberOfSamplesPerTrace == length(samples) || throw(ErrorException(@sprintf("wrong samples length %d, expecting %d", length(samples), trs.numberOfSamplesPerTrace)))
  trs.sampleType == eltype(samples) || throw(ErrorException(@sprintf("wrong samples type %s, expecting %s", eltype(samples), trs.sampleType)))

  bytesinsamples = trs.numberOfSamplesPerTrace * sizeof(trs.sampleType)
  pos = (idx-1) * bytesinsamples
  if position(trs.samplesFileDescriptor) != pos
    seek(trs.samplesFileDescriptor, pos)
  end

  if trs.sampleType != UInt8
    if ltoh(ENDIAN_BOM) != ENDIAN_BOM
      samples = map(htol, samples)
    end
    samples = reinterpret(UInt8, samples)
  end

  write(trs.samplesFileDescriptor, samples)
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

function close(trs::SplitBinary)
  close(trs.samplesFileDescriptor)
  close(trs.dataFileDescriptor)
end
