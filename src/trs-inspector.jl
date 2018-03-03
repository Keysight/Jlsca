# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export InspectorTrace

using Base.get
import Base.close

# Inspector trace set implementation
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
  postProcInstance
  bgtask
  tracesReturned
  filename
  filePosition
  writeable::Bool
  lengthPosition::Int
  bitshack::Bool
  colRange::Nullable{Range}

  # to open an existing file
  function InspectorTrace(filename::String, bitshack::Bool = false)
    (titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, lengthPosition, fileDescriptor) = readInspectorTrsHeader(filename, bitshack)
    new(titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, [], [], Union, Union, 0, filename, traceBlockPosition, false, lengthPosition, bitshack, Nullable{Range}())
  end

  # to create a new one
  function InspectorTrace(filename::String, dataSpace::Int, sampleType::Type, numberOfSamplesPerTrace::Int)
    return InspectorTrace(filename,dataSpace,sampleType,numberOfSamplesPerTrace,0)
  end

  function InspectorTrace(filename::String, dataSpace::Int, sampleType::Type, numberOfSamplesPerTrace::Int, titleSpace::Int)
    !isfile(filename) || throw(ErrorException(@sprintf("file %s exists!", filename)))

    (titleSpace, traceBlockPosition, lengthPosition, fileDescriptor) = writeInspectorTrsHeader(filename, dataSpace, sampleType, numberOfSamplesPerTrace, titleSpace)
    new(titleSpace, Nullable(0), dataSpace, sizeof(sampleType), sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, [], [], Union, Union, 0, filename, traceBlockPosition, true, lengthPosition, false)
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
const GlobalTitleSpace = 0x46
const GlobalTitleSpaceLength = 4

const Description = 0x47

const Offset = 0x48
const OffsetLength = 4

const TraceBlock = 0x5F

const CodingByte = 0x01
const CodingShort = 0x02
const CodingInt = 0x04
const CodingFloat = 0x14

pipe(trs::InspectorTrace) = isa(trs.fileDescriptor, Base.PipeEndpoint)

# hack
import Base.skip
skip(fd::Base.PipeEndpoint, x::Integer) = read(fd, x)

length(trs::InspectorTrace) = isnull(trs.numberOfTraces) ? typemax(Int) : get(trs.numberOfTraces)

# read the header of a Riscure Inspector trace set (TRS)
function readInspectorTrsHeader(filename, bitshack::Bool)
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
      lengthPosition = 0

      # if verbose
      #   if seekable
      #     @printf("Opening Inspector trs file %s ..\n", filename)
      #   else
      #     @printf("Opening Inspector trs from stdin ..\n")
      #   end
      # end

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
          if seekable
            lengthPosition = position(f)
          else
            lengthPosition = -1
          end
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
            sampleType = Int16
            sampleSpace = 2
          elseif sampleCoding == CodingByte
            sampleType = UInt8
            sampleSpace = 1
          end
        else
          # if verbose
            println("[x] Skipping unknown tag $tag with length $length")
          # end
          read(f, length)
        end
      end

      if bitshack
        if (numberOfSamplesPerTrace * sampleSpace) % 8 != 0
          @printf("Warning: bithack enabled: ignoring trailing %d samples that are not 8 byte aligned !!!1\n", (numberOfSamplesPerTrace * sampleSpace) % 8)
        end
        # numberOfSamplesPerTrace = div((sampleSpace * numberOfSamplesPerTrace), 8)
        # sampleType = UInt64
        # sampleSpace = 8
      end

      @printf("Opened %s, #traces %s, #samples %d (%s), #data %d%s\n", filename, isnull(numberOfTraces) ? "unknown" : @sprintf("%d", get(numberOfTraces)), numberOfSamplesPerTrace, sampleType, dataSpace, titleSpace > 0 ? ", #title $titleSpace" : "")

      return (titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, lengthPosition, f)
  catch e
      close(f)
      rethrow(e)
  end
end

function close(trs::InspectorTrace)
  if trs.writeable
    seek(trs.fileDescriptor, trs.lengthPosition)
    write(trs.fileDescriptor, htol(convert(UInt32, length(trs))))
    if verbose
      @printf("Wrote %d traces in %s\n", length(trs), trs.filename)
    end
  end

  close(trs.fileDescriptor)
end

calcFilePositionForIdx(trs::InspectorTrace, idx::Int) = trs.traceBlockPosition + (idx-1) * (trs.titleSpace + trs.dataSpace + trs.numberOfSamplesPerTrace * trs.sampleSpace)

# read data for a single trace from an Inspector trace set
function readData(trs::InspectorTrace, idx)
  position = calcFilePositionForIdx(trs, idx)

  if trs.filePosition != position
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, position)
    trs.filePosition = position
  end

  skip(trs.fileDescriptor, trs.titleSpace)
  data = read(trs.fileDescriptor, trs.dataSpace)
  length(data) == trs.dataSpace || throw(EOFError())
  trs.filePosition += trs.dataSpace

  return data
end

# write data for a single trace from an Inspector trace set
function writeData(trs::InspectorTrace, idx, data::Vector{UInt8})
  trs.dataSpace == length(data) || throw(ErrorException(@sprintf("wrong data length %d, expecting %d", length(data), trs.dataSpace)))
  position = calcFilePositionForIdx(trs, idx)

  if trs.filePosition != position
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, position)
    trs.filePosition = position
  end

  skip(trs.fileDescriptor, trs.titleSpace)
  write(trs.fileDescriptor, data)
  trs.filePosition += trs.dataSpace

  return data
end

export readTitle

"""
Inspector specific function to read metadata (i.e. a title) from an `InspectorTrace` instance `trs` at index `idx`.
"""
function readTitle(trs::InspectorTrace, idx)
  position = calcFilePositionForIdx(trs, idx)

  if trs.filePosition != position
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, position)
    trs.filePosition = position
  end

  data = read(trs.fileDescriptor, trs.titleSpace)
  length(data) == trs.titleSpace || throw(EOFError())
  trs.filePosition += trs.titleSpace

  return data
end

export writeTitle

"""
Inspector specific function to write metadata `data` (a byte array, should be a readable ascii string for Inspector) from an `InspectorTrace` instance `trs` at index `idx`.
"""
function writeTitle(trs::InspectorTrace, idx, data::Vector{UInt8})
  trs.titleSpace >= length(data) || throw(ErrorException(@sprintf("wrong title length %d, expecting <= %d", length(data), trs.titleSpace)))
  position = calcFilePositionForIdx(trs, idx)

  if trs.filePosition != position
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, position)
    trs.filePosition = position
  end

  write(trs.fileDescriptor, data)
  trs.filePosition += trs.titleSpace

  return data
end

# read samples for a single trace from an Inspector trace set
function readSamples(trs::InspectorTrace, idx)
  pos = calcFilePositionForIdx(trs, idx)
  pos += trs.titleSpace
  pos += trs.dataSpace

  if trs.filePosition != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
    trs.filePosition = pos
  end

  if trs.bitshack
    samples = Vector{UInt64}(div(trs.numberOfSamplesPerTrace * trs.sampleSpace, 8))
    read!(trs.fileDescriptor, samples)
    trs.filePosition = position(trs.fileDescriptor)
  else
    samples = read(trs.fileDescriptor, trs.sampleType, trs.numberOfSamplesPerTrace)
    trs.filePosition += trs.numberOfSamplesPerTrace * trs.sampleSpace
  end

  if trs.sampleType != UInt8
    if ltoh(ENDIAN_BOM) != ENDIAN_BOM
      samples = map(ltoh, samples)
    end
  end

  return samples
end

# write samples for a single trace into an Inspector trace set
function writeSamples(trs::InspectorTrace, idx, samples::Vector)
  trs.numberOfSamplesPerTrace == length(samples) || throw(ErrorException(@sprintf("wrong samples length %d, expecting %d", length(samples), trs.numberOfSamplesPerTrace)))
  trs.sampleType == eltype(samples) || throw(ErrorException(@sprintf("wrong samples type %s, expecting %s", eltype(samples), trs.sampleType)))

  position = calcFilePositionForIdx(trs, idx)
  position += trs.titleSpace
  position += trs.dataSpace

  if trs.filePosition != position
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, position)
    trs.filePosition = position
  end

  if trs.sampleType != UInt8
    if ltoh(ENDIAN_BOM) != ENDIAN_BOM
      samples = map(htol, samples)
    end
  end

  write(trs.fileDescriptor, samples)
  trs.filePosition += trs.numberOfSamplesPerTrace * trs.sampleSpace
  trs.numberOfTraces = Nullable(max(idx, get(trs.numberOfTraces)))

  return samples
end

function writeInspectorTrsHeader(filename::String, dataSpace::Int, sampleType::Type, numberOfSamplesPerTrace::Int, titleSpace::Int)

  sampleCoding = Union
  if sampleType == UInt8
    sampleCoding = CodingByte
  elseif sampleType == Int16
    sampleCoding = CodingShort
  elseif sampleType == UInt32
    sampleCoding = CodingInt
  elseif sampleType == Float32
    sampleCoding = CodingFloat
  else
    @printf("[x] Not suppoerpeopsodpsofd sample type %s\n", sampleType)
    return
  end

  if verbose
    @printf("Creating Inspector trs file %s\n", filename)
    @printf("#samples: %d\n", numberOfSamplesPerTrace)
    @printf("#data:    %d\n", dataSpace)
    @printf("type:     %s\n", string(sampleType))
    if titleSpace > 0
      @printf("#title:   %s\n", string(titleSpace))
    end

  end

  fd = open(filename, "w+")

  write(fd, convert(UInt8, TitleSpace))
  write(fd, convert(UInt8, TitleSpaceLength))
  write(fd, htol(convert(UInt8, titleSpace)))

  write(fd, convert(UInt8, SampleCoding))
  write(fd, convert(UInt8, SampleCodingLength))
  write(fd, htol(convert(UInt8, sampleCoding)))

  write(fd, convert(UInt8, DataSpace))
  write(fd, convert(UInt8, DataSpaceLength))
  write(fd, htol(convert(UInt16, dataSpace)))

  write(fd, convert(UInt8, NumberOfSamplesPerTrace))
  write(fd, convert(UInt8, NumberOfSamplesPerTraceLength))
  write(fd, htol(convert(UInt32, numberOfSamplesPerTrace)))

  write(fd, convert(UInt8, NumberOfTraces))
  write(fd, convert(UInt8, NumberOfTracesLength))
  lengthPosition = position(fd)
  write(fd, htol(convert(UInt32, 0)))

  write(fd, convert(UInt8, TraceBlock))
  write(fd, convert(UInt8, 0))
  traceBlockPosition = position(fd)

  return (titleSpace, traceBlockPosition, lengthPosition, fd)
end
