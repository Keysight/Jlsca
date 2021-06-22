# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export InspectorTrace

using Base:get
import Base:close

verbose = true

# Inspector trace set implementation
mutable struct InspectorTrace <: Traces
  titleSpace::Int
  numberOfTraces::Union{Missing,Int}
  dataSpace::Int
  sampleSpace::Int
  sampleType::Type
  numberOfSamplesPerTrace::Int
  traceBlockPosition::Int
  fileDescriptor::IOStream
  filename::String
  filePosition::Int
  writeable::Bool
  lengthPosition::Int
  readrangecheckonce::Bool
  scaleX::Union{Missing,Float32}
  offsetX::Union{Missing,Int32}
  meta::MetaData

  # to open an existing file
  function InspectorTrace(filename::String; forceNtraces::Union{Missing,Int}=missing)
    (titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, lengthPosition, fileDescriptor, scaleX, offsetX) = readInspectorTrsHeader(filename)
    if !ismissing(forceNtraces)
      numberOfTraces = forceNtraces
    end
    new(titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, filename, traceBlockPosition, false, lengthPosition, true, scaleX, offsetX, MetaData())
  end

  # to create a new one
  # function InspectorTrace(filename::String, dataSpace::Int, sampleType::Type, numberOfSamplesPerTrace::Int)
  #   return InspectorTrace(filename,dataSpace,sampleType,numberOfSamplesPerTrace,0)
  # end

  function InspectorTrace(
    filename::String, 
    dataSpace::Int, 
    sampleType::Type, 
    numberOfSamplesPerTrace::Int;
    titleSpace::Int=0,
    scaleX::Union{Missing,Float32}=missing,
    offsetX::Union{Missing,Int32}=missing)
    !isfile(filename) || throw(ErrorException(@sprintf("file %s exists!", filename)))

    (titleSpace, traceBlockPosition, lengthPosition, fileDescriptor) = writeInspectorTrsHeader(filename, dataSpace, sampleType, numberOfSamplesPerTrace, titleSpace, scaleX, offsetX)
    new(titleSpace, 0, dataSpace, sizeof(sampleType), sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, filename, traceBlockPosition, true, lengthPosition, true, scaleX, offsetX, MetaData())
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
const OffsetX = 0x48
const ScaleX = 0x4b

const Description = 0x47

const Offset = 0x48
const OffsetLength = 4

const TraceBlock = 0x5F

const CodingByte = 0x01
const CodingShort = 0x02
const CodingInt = 0x04
const CodingFloat = 0x14

# hack
import Base.skip
skip(fd::Base.PipeEndpoint, x::Integer) = read(fd, x)

length(trs::InspectorTrace) = ismissing(trs.numberOfTraces) ? typemax(Int) : trs.numberOfTraces
nrsamples(trs::InspectorTrace) = trs.numberOfSamplesPerTrace
sampletype(trs::InspectorTrace) = Vector{trs.sampleType}()
meta(trs::InspectorTrace) = trs.meta

function length2type(x)
  if x == 1
    t = UInt8
  elseif x == 2
    t = UInt16
  elseif x == 4
    t = UInt32
  elseif x == 8
    t = UInt64
  else
    error("unsupported type")
  end
end

# read the header of a Riscure Inspector trace set (TRS)
function readInspectorTrsHeader(filename)
    if filename != "-"
      f = open(filename, "r")
    else
      f = stdin
    end

    seekable = !isa(f, Base.PipeEndpoint)

    try
      done = false
      titleSpace = 0
      numberOfTraces = 
      dataSpace = 0
      sampleSpace = 0
      sampleType = UInt8
      numberOfSamplesPerTrace = 0
      traceBlockPosition = 0
      lengthPosition = 0
      scaleX = missing
      offsetX = missing

      # if verbose
      #   if seekable
      #     @printf("Opening Inspector trs file %s ..\n", filename)
      #   else
      #     @printf("Opening Inspector trs from stdin ..\n")
      #   end
      # end

      while !done
        mypos = position(f)
        tag = read(f, UInt8)
        x = read(f, UInt8)

        if x & 0x80 == 0x80
          lolwut = x & 0x7f
          x = 0
          for i in 1:lolwut
            x += (UInt(read(f, UInt8)) << (8*(i-1)))
          end
        end

        if tag == TraceBlock && x == 0
          if seekable
            traceBlockPosition = position(f)
          end
          done = true
        elseif tag == TitleSpace
          titleSpace = read(f, length2type(x))
        elseif tag == NumberOfTraces
          if seekable
            lengthPosition = position(f)
          else
            lengthPosition = -1
          end
          numberOfTraces = ltoh(read(f, length2type(x)))
        elseif tag == DataSpace
          dataSpace = ltoh(read(f, length2type(x)))
        elseif tag == NumberOfSamplesPerTrace
          numberOfSamplesPerTrace = ltoh(read(f, length2type(x)))
        elseif tag == SampleCoding
          sampleCoding = read(f, length2type(x))
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
        elseif tag == ScaleX
          scaleX = ltoh(read(f,Float32))
        elseif tag == OffsetX
          offsetX = ltoh(read(f,Int32))
        else
          # if verbose
            println("[x] Skipping unknown tag 0x$(string(tag,base=16)) with length $x @ position $mypos")
          # end
          read(f, x)
        end
      end

      @printf("Opened %s, #traces %s, #samples %d (%s), #data %d%s\n", filename, ismissing(numberOfTraces) ? "unknown" : @sprintf("%d", numberOfTraces), numberOfSamplesPerTrace, sampleType, dataSpace, titleSpace > 0 ? ", #title $titleSpace" : "")

      return (titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, lengthPosition, f, scaleX, offsetX)
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
  pos = calcFilePositionForIdx(trs, idx)

  if position(trs.fileDescriptor) != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
  end

  skip(trs.fileDescriptor, trs.titleSpace)
  data = read(trs.fileDescriptor, trs.dataSpace)
  length(data) == trs.dataSpace || throw(EOFError())

  return data
end

# write data for a single trace from an Inspector trace set
function writeData(trs::InspectorTrace, idx, data::AbstractVector{UInt8})
  trs.dataSpace == length(data) || throw(ErrorException(@sprintf("wrong data length %d, expecting %d", length(data), trs.dataSpace)))
  pos = calcFilePositionForIdx(trs, idx)

  if position(trs.fileDescriptor) != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
  end

  skip(trs.fileDescriptor, trs.titleSpace)
  write(trs.fileDescriptor, data)

  return data
end

export readTitle

"""
Inspector specific function to read metadata (i.e. a title) from an `InspectorTrace` instance `trs` at index `idx`.
"""
function readTitle(trs::InspectorTrace, idx)
  pos = calcFilePositionForIdx(trs, idx)

  if position(trs.fileDescriptor) != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
   end

  data = read(trs.fileDescriptor, trs.titleSpace)
  length(data) == trs.titleSpace || throw(EOFError())

  return data
end

export writeTitle

"""
Inspector specific function to write metadata `data` (a byte array, should be a readable ascii string for Inspector) from an `InspectorTrace` instance `trs` at index `idx`.
"""
function writeTitle(trs::InspectorTrace, idx, data::AbstractVector{UInt8})
  trs.titleSpace >= length(data) || throw(ErrorException(@sprintf("wrong title length %d, expecting <= %d", length(data), trs.titleSpace)))
  pos = calcFilePositionForIdx(trs, idx)

  if position(trs.fileDescriptor) != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
  end

  write(trs.fileDescriptor, data)

  return data
end

function readSamples(trs::InspectorTrace, idx::Int)
    readSamples(trs, idx, 1:trs.numberOfSamplesPerTrace)
end

# read samples for a single trace from an Inspector trace set
function readSamples(trs::InspectorTrace, idx::Int, r::UnitRange)
  if trs.readrangecheckonce
    issubset(r,1:trs.numberOfSamplesPerTrace) || error("requested range $r not in trs sample space $(1:trs.numberOfSamplesPerTrace)")
    trs.readrangecheckonce = false
  end
  pos = calcFilePositionForIdx(trs, idx)
  pos += trs.titleSpace
  pos += trs.dataSpace
  pos += (r[1]-1) * trs.sampleSpace

  if position(trs.fileDescriptor) != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
  end
  
  samples = Vector{trs.sampleType}(undef,length(r))
  read!(trs.fileDescriptor, samples)

  if trs.sampleType != UInt8
    if ltoh(ENDIAN_BOM) != ENDIAN_BOM
      samples = map(ltoh, samples)
    end
  end

  return samples
end

export getXrange

function getXrange(trs::InspectorTrace)
  xrange = zeros(Float64,nrsamples(trs,true))
  xoffset = trs.offsetX
  xstep = trs.scaleX

  pcr = meta(trs).preColRange
  xoffsetextra = 0
  if !ismissing(pcr)
    xoffsetextra = pcr[1]
  end

  if ismissing(xstep)
    error("no xstep in this trace set")
  end

  if ismissing(xoffset)
    xoffset = 0
  end

  xoffset += xoffsetextra

  xrange[1] =  xoffset * xstep + .5 * xstep
  for i in 2:length(xrange)
    xrange[i] = xrange[i-1] + xstep
  end

  return xrange
end

# write samples for a single trace into an Inspector trace set
function writeSamples(trs::InspectorTrace, idx, samples::AbstractVector)
  trs.numberOfSamplesPerTrace == length(samples) || throw(ErrorException(@sprintf("wrong samples length %d, expecting %d", length(samples), trs.numberOfSamplesPerTrace)))
  trs.sampleType == eltype(samples) || throw(ErrorException(@sprintf("wrong samples type %s, expecting %s", eltype(samples), trs.sampleType)))

  pos = calcFilePositionForIdx(trs, idx)
  pos += trs.titleSpace
  pos += trs.dataSpace

  if position(trs.fileDescriptor) != pos
    # this is going to throw an exception when reading from stdin
    seek(trs.fileDescriptor, pos)
  end

  if trs.sampleType != UInt8
    if ltoh(ENDIAN_BOM) != ENDIAN_BOM
      samples = map(htol, samples)
    end
  end

  write(trs.fileDescriptor, samples)
  trs.numberOfTraces = max(idx, trs.numberOfTraces)

  return samples
end

function writeInspectorTrsHeader(filename::String, dataSpace::Int, sampleType::Type, numberOfSamplesPerTrace::Int, titleSpace::Int, scaleX::Union{Missing,Float32}, offsetX::Union{Missing,Int32})

  sampleCoding = Union
  if sampleType == UInt8 || sampleType == Int8
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

  if !ismissing(scaleX)
    write(fd, convert(UInt8, ScaleX))
    write(fd, convert(UInt8, 4))
    write(fd, htol(scaleX))
  end

  if !ismissing(offsetX)
    write(fd, convert(UInt8, OffsetX))
    write(fd, convert(UInt8, 4))
    write(fd, htol(offsetX))
  end

  # hello = codeunits("File created Jlsca!!1!")
  # write(fd, 0x47 |> UInt8)
  # write(fd, length(hello) |> UInt8)
  # write(fd, hello)

  write(fd, convert(UInt8, NumberOfTraces))
  write(fd, convert(UInt8, NumberOfTracesLength))

  lengthPosition = position(fd)
  write(fd, htol(convert(UInt32, 0)))

  write(fd, convert(UInt8, TraceBlock))
  write(fd, convert(UInt8, 0))
  traceBlockPosition = position(fd)

  return (titleSpace, traceBlockPosition, lengthPosition, fd)
end
