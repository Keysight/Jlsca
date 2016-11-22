# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export InspectorTrace,readTrace,writeToTraces

# Inspector trace implementation
type InspectorTrace <: Trace
  titleSpace
  numberOfTraces::Nullable{Int}
  dataSpace
  sampleSpace
  sampleType
  numberOfSamplesPerTrace
  traceBlockPosition
  fileDescriptor
  passes
  dataPasses
  postProcType
  postProcArguments
  postProcInstance
  bgtask
  tracesReturned
  filename
  prevIdx

  function InspectorTrace(filename)
    (titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor) = readInspectorTrsHeader(filename)
    new(titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, [], [], Union, nothing, Union, Union, 0, filename, 0)
  end
end

const NumberOfTraces = 0x41
const NumberOfTracesLength = 4
const NumberOfSamplesPerTrace = 0x42
const NumberOfSamplesPerTraceLength  = 4
const SampleCoding = 0x43
const SampleCodingLength = 1
const DataSpace = 0x44
const DataSpaceLength = 2
const TitleSpace = 0x45
const TitleSpaceLength = 1
const Description = 0x47
const TraceBlock = 0x5F

const CodingByte = 0x01
const CodingShort = 0x02
const CodingInt = 0x04
const CodingFloat = 0x14

# debugging
const verbose = true

pipe(trs::InspectorTrace) = isa(trs.fileDescriptor, Base.PipeEndpoint)

length(trs::InspectorTrace) = isnull(trs.numberOfTraces) ? typemax(Int) : get(trs.numberOfTraces)

# read the header of a Riscure Inspector trace set (TRS)
function readInspectorTrsHeader(filename)
    if filename != "-"
      f = open(filename, "r")
    else
      f = STDIN
    end

    seekable = !isa(f, Base.PipeEndpoint)

    try
      done = false
      titleSpace = 0
      numberOfTraces = Nullable()
      dataSpace = 0
      sampleSpace = 0
      sampleType = UInt8
      numberOfSamplesPerTrace = 0
      traceBlockPosition = 0

      if verbose
        if seekable
          @printf("Opening Inspector trs file %s ..\n", filename)
        else
          @printf("Opening Inspector trs from stdin ..\n")
        end
      end

      while !done
        tag = read(f, UInt8)
        length = read(f, UInt8)

        if length & 0x80 == 0x80
          lolwut = length & 0x7f
          length = 0
          for i in 1:lolwut
            length += (UInt(read(f, UInt8)) << (8*(i-1)))
          end
        end

        if tag == TraceBlock && length == 0
          if seekable
            traceBlockPosition = position(f)
          end
          done = true
        elseif tag == TitleSpace && length == TitleSpaceLength
          titleSpace = read(f, UInt8)
        elseif tag == NumberOfTraces && length == NumberOfTracesLength
          numberOfTraces = Nullable(ltoh(read(f, UInt32)))
        elseif tag == DataSpace && length == DataSpaceLength
          dataSpace = ltoh(read(f, UInt16))
        elseif tag == NumberOfSamplesPerTrace && length == NumberOfSamplesPerTraceLength
          numberOfSamplesPerTrace = ltoh(read(f, UInt32))
        elseif tag == SampleCoding && length == SampleCodingLength
          sampleCoding = read(f, UInt8)
          if sampleCoding == CodingFloat
            sampleType = Float32
            sampleSpace = 4
          elseif sampleCoding == CodingInt
            sampleType = UInt32
            sampleSpace = 4
          elseif sampleCoding == CodingShort
            sampleType = UInt16
            sampleSpace = 2
          elseif sampleCoding == CodingByte
            sampleType = UInt8
            sampleSpace = 1
          end
        else
          if verbose
            println("[x] Skipping unknown tag $tag with length $length")
          end
          read(f, length)
        end
      end

      if verbose
        if !isnull(numberOfTraces)
          @printf("#traces:  %d\n", get(numberOfTraces))
        end
        @printf("#samples: %d\n", numberOfSamplesPerTrace)
        @printf("#data:    %d\n", dataSpace)
        @printf("type:     %s\n", string(sampleType))
      end
      return (titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, f)

  catch e
      close(f)
      rethrow(e)
  end
end

# read a single trace from an Inspector trace set
function readTrace(trs::InspectorTrace, idx)
    f = trs.fileDescriptor
    dataSpace = trs.dataSpace
    numberOfSamplesPerTrace = trs.numberOfSamplesPerTrace
    sampleSpace = trs.sampleSpace
    titleSpace = trs.titleSpace
    traceBlockPosition = trs.traceBlockPosition
    sampleType = trs.sampleType

    (data, trace) = (nothing, nothing)

    if !(trs.prevIdx + 1 == idx)
      # this is going to throw an exception when reading from stdin
      seek(f, traceBlockPosition + (idx-1) * (titleSpace + dataSpace + numberOfSamplesPerTrace * sampleSpace))
    end

    title = read(f, titleSpace)
    data = read(f, dataSpace)
    trace = read(f, numberOfSamplesPerTrace * sampleSpace)

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

    return (data, trace)
end

# writes a Matrix of data and samples to an Inspector file, only used for creating simulation traces at the moment
function writeToTraces(filename, data::Matrix, samples::Matrix)
  (numberOfTraces, nrSamples) = size(samples)
  (bla, dataSpace) = size(data)

  if bla != numberOfTraces
    @printf("[x] data rows %d != sample rows %d\n", bla, numberOfTraces)
    return
  end

  sampleCoding = Union
  if eltype(samples) == UInt8
    sampleCoding = CodingByte
  elseif eltype(samples) == UInt16
    sampleCoding = CodingShort
  elseif eltype(samples) == UInt32
    sampleCoding = CodingInt
  elseif eltype(samples) == Float32
    sampleCoding = CodingFloat
  else
    @printf("[x] Not suppoerpeopsodpsofd sample type %s\n", string(eltype(samples)))
    return
  end


  fd = open(filename, "w")

  write(fd, convert(UInt8, TitleSpace))
  write(fd, convert(UInt8, TitleSpaceLength))
  write(fd, htol(convert(UInt8, 0)))

  write(fd, convert(UInt8, SampleCoding))
  write(fd, convert(UInt8, SampleCodingLength))
  write(fd, htol(convert(UInt8, sampleCoding)))

  write(fd, convert(UInt8, DataSpace))
  write(fd, convert(UInt8, DataSpaceLength))
  write(fd, htol(convert(UInt16, dataSpace)))

  write(fd, convert(UInt8, NumberOfSamplesPerTrace))
  write(fd, convert(UInt8, NumberOfSamplesPerTraceLength))
  write(fd, htol(convert(UInt32, nrSamples)))

  write(fd, convert(UInt8, NumberOfTraces))
  write(fd, convert(UInt8, NumberOfTracesLength))
  write(fd, htol(convert(UInt32, numberOfTraces)))

  write(fd, convert(UInt8, TraceBlock))
  write(fd, convert(UInt8, 0))

  for i in 1:numberOfTraces
    write(fd, data[i,:])

    if eltype(samples) == UInt8
      write(fd, samples[i,:])
    else
      write(fd, htol(reinterpret(UInt8, samples[i,:])))
    end
  end

  close(fd)

end

# writes a Traces object to an Inspector traceset file
function writeToTraces(filename, trs::Trace, start::Int=1, endd::Int=(length(trs)-start+1))
  (data,samples) = trs[1]
  dataSpace = length(data)
  nrSamples = length(samples)
  numberOfTraces = length(trs)

  sampleCoding = Union
  if eltype(samples) == UInt8
    sampleCoding = CodingByte
  elseif eltype(samples) == UInt16 || eltype(samples) == Int16
    sampleCoding = CodingShort
  elseif eltype(samples) == UInt32
    sampleCoding = CodingInt
  elseif eltype(samples) == Float32
    sampleCoding = CodingFloat
  else
    @printf("[x] Not suppoerpeopsodpsofd sample type %s\n", string(eltype(samples)))
    return
  end

  fd = open(filename, "w")

  write(fd, convert(UInt8, TitleSpace))
  write(fd, convert(UInt8, TitleSpaceLength))
  write(fd, htol(convert(UInt8, 0)))

  write(fd, convert(UInt8, SampleCoding))
  write(fd, convert(UInt8, SampleCodingLength))
  write(fd, htol(convert(UInt8, sampleCoding)))

  write(fd, convert(UInt8, DataSpace))
  write(fd, convert(UInt8, DataSpaceLength))
  write(fd, htol(convert(UInt16, dataSpace)))

  write(fd, convert(UInt8, NumberOfSamplesPerTrace))
  write(fd, convert(UInt8, NumberOfSamplesPerTraceLength))
  write(fd, htol(convert(UInt32, nrSamples)))

  write(fd, convert(UInt8, NumberOfTraces))
  write(fd, convert(UInt8, NumberOfTracesLength))
  write(fd, htol(convert(UInt32, endd-start+1)))

  write(fd, convert(UInt8, TraceBlock))
  write(fd, convert(UInt8, 0))

  for i in start:endd
    write(fd, trs[i][1])

    if eltype(samples) == UInt8
      write(fd, trs[i][2])
    else
      write(fd, htol(reinterpret(UInt8, trs[i][2])))
    end
  end

  close(fd)

end
