# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

export InspectorTraceMM,readData,readSamples

using Base.get
import Base.close

# Inspector trace set implementation
type InspectorTraceMM <: Trace
  mmData::Array
  mmSamples::Array
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
  writeable::Bool
  lengthPosition::Int

  # to open an existing file
  function InspectorTraceMM(filename::String)
    (mmData, mmSamples, titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, lengthPosition, fileDescriptor) = readInspectorTrsHeaderMM(filename)
    new(mmData, mmSamples, titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, [], [], Union, nothing, Union, Union, 0, filename, false, lengthPosition)
  end

  # # to create a new one
  # function InspectorTraceMM(filename::String, dataSpace::Int, sampleType::Type, numberOfSamplesPerTrace::Int)
  #   !isfile(filename) || throw(ErrorException(@sprintf("file %s exists!", filename)))
  #
  #   (mm, titleSpace, traceBlockPosition, lengthPosition, fileDescriptor) = writeInspectorTrsHeader(filename, dataSpace, sampleType, numberOfSamplesPerTrace)
  #   new(mm, titleSpace, Nullable(0), dataSpace, sizeof(sampleType), sampleType, numberOfSamplesPerTrace, traceBlockPosition, fileDescriptor, [], [], Union, nothing, Union, Union, 0, filename, traceBlockPosition, true, lengthPosition)
  # end
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

pipe(trs::InspectorTraceMM) = isa(trs.fileDescriptor, Base.PipeEndpoint)

length(trs::InspectorTraceMM) = isnull(trs.numberOfTraces) ? typemax(Int) : get(trs.numberOfTraces)

# read the header of a Riscure Inspector trace set (TRS)
function readInspectorTrsHeaderMM(filename)
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
          lengthPosition = position(f)
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

      if ((dataSpace+titleSpace) % sizeof(sampleType)) != 0
        throw(ErrorException(@sprintf("dataSpace+titleSpace of trace set must be multiples of %d bytes", sizeof(sampleType))))
      end

      return (Mmap.mmap(f,Vector{UInt8}), Mmap.mmap(f,Vector{sampleType}), titleSpace, numberOfTraces, dataSpace, sampleSpace, sampleType, numberOfSamplesPerTrace, traceBlockPosition, lengthPosition, f)

  catch e
      close(f)
      rethrow(e)
  end
end

function close(trs::InspectorTraceMM)
  if trs.writeable
    seek(trs.fileDescriptor, trs.lengthPosition)
    write(trs.fileDescriptor, htol(convert(UInt32, length(trs))))
    if verbose
      @printf("Wrote %d traces in %s\n", length(trs), trs.filename)
    end
  end


  finalize(trs.mmData)
  finalize(trs.mmSamples)
  close(trs.fileDescriptor)
end

calcPositionForData(trs::InspectorTraceMM, idx::Int) = (idx-1) * (trs.titleSpace + trs.dataSpace + trs.numberOfSamplesPerTrace * trs.sampleSpace)

# read data for a single trace from an Inspector trace set
function readData(trs::InspectorTraceMM, idx)
  position = calcPositionForData(trs, idx)

  start = (position + trs.titleSpace)
  data = view(trs.mmData, (start+1):(start+trs.dataSpace))

  return data
end

calcPositionForSamples(trs::InspectorTraceMM, idx::Int) = (idx-1) * (div(trs.titleSpace + trs.dataSpace, trs.sampleSpace) + trs.numberOfSamplesPerTrace)

# read samples for a single tracec from an Inspector trace set
function readSamples(trs::InspectorTraceMM, idx)
  position = calcPositionForSamples(trs, idx)

  start = position + div(trs.dataSpace + trs.titleSpace, trs.sampleSpace)

  samples = view(trs.mmSamples, (start+1):(start + trs.numberOfSamplesPerTrace))

  return samples
end
