# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
# Author: Cees-Bart Breunesse
#
# PoC using rapid block mode of the Picoscope 5203 on Riscure's Pinata board.
#
#  Look for main(). Running this without changes acquires ~245K traces of randomly interleaved TVLA r5 sbox semi-constant and AES MixColumn semi-constant data. Should not take more than 17 minutes. It dumps the traces into split binary files, you'll need to run splitbinary2ins.jl in order to create Inspector traces if you want to import them there.
#
# Assumes many things, like
#  - the Pinata board to be at /dev/ttyUSB0
#  - you installed the Picotech Linux drivers https://www.picotech.com/downloads/linux
#  - you installed the Julia libserialport wrapper https://github.com/andrewadare/LibSerialPort.jl
#
# Also:
#  - I've not tested this on Windows
#  - This script doesn't do anything gracefully, like terminating on errors. Be careful.
#  - Many of the scope parameters are hard coded (measure on channel B, trigger on external, for example)
#  - Things will break when using more than 1 measuring channel
#
# Datasheet for the scope I used as reference is here:
# https://www.picotech.com/download/manuals/ps5000pg-en-1.pdf

using ProgressMeter

using Jlsca.Aes

using LibSerialPort
import LibSerialPort.sp_blocking_read
import LibSerialPort.Port
import LibSerialPort.handle_error
import LibSerialPort.loc

const model = "ps5000"
const libname = @sprintf("lib%s", model)
const OpenUnit = @sprintf("%sOpenUnit", model)
const CloseUnit = @sprintf("%sCloseUnit", model)
const SetChannel = @sprintf("%sSetChannel", model)
const GetTimebase = @sprintf("%sGetTimebase", model)
const SetDataBufferBulk = @sprintf("%sSetDataBufferBulk", model)
const GetValuesBulk = @sprintf("%sGetValuesBulk", model)
const SetNoOfCaptures = @sprintf("%sSetNoOfCaptures", model)
const SetEts = @sprintf("%sSetEts", model)
const SetSimpleTrigger = @sprintf("%sSetSimpleTrigger", model)
const RunBlock = @sprintf("%sRunBlock", model)
const IsReady = @sprintf("%sIsReady", model)
const MemorySegments = @sprintf("%sMemorySegments", model)
const GetValuesTriggerTimeOffsetBulk64 = @sprintf("%sGetValuesTriggerTimeOffsetBulk64", model)
const GetTriggerTimeOffset64 = @sprintf("%sGetTriggerTimeOffset64", model)
const SetSigGenBuiltIn = @sprintf("%sSetSigGenBuiltIn", model)

@enum InputChannel PS_CHANNEL_A PS_CHANNEL_B PS_CHANNEL_C PS_CHANNEL_D PS_CHANNEL_EXT
@enum VoltageRange PS_10MV PS_20MV PS_50MV PS_100MV PS_200MV PS_500MV PS_1V  PS_2V PS_5V PS_10V PS_20V PS_50V
@enum EtsMode PS_ETS_OFF PS_ETS_FAST PS_ETS_SLOW
@enum ThresholdDirection ABOVE BELOW RISING FALLING RISING_OR_FALLING

function openUnit(handle::Ref{Cshort})
  val = ccall((OpenUnit, libname), Int32, (Ref{Cshort},), handle)
  if val != 0
    @printf("error %s: %d\n", OpenUnit, val)
  end
end

function closeUnit(handle::Ref{Cshort})
  val = ccall((CloseUnit, libname), Int32, (Cshort,), handle.x)
  if val != 0
    @printf("error %s: %d\n", CloseUnit, val)
  end
end

function setChannel(handle::Ref{Cshort}, channel::InputChannel, enabled::Bool, dcCoupling::Bool, range::VoltageRange)
  val = ccall((SetChannel, libname), Int32, (Cshort,Cint,Cshort,Cshort,Cint), handle.x, channel, enabled ? 1 : 0, dcCoupling ? 1 : 0, range)
  if val != 0
    @printf("error %s: %d\n", SetChannel, val)
  end
end

function setEts(handle::Ref{Cshort}, mode::EtsMode, etsCycles::Int, etsInterleave::Int)
  sampleTimePicoseconds = Ref{Clong}(0)
  val = ccall((SetEts, libname), Int32, (Cshort,Cint,Cshort,Cshort,Ref{Clong}), handle.x, mode, etsCycles, etsInterleave, sampleTimePicoseconds)
  if val != 0
    @printf("error %s: %d\n", SetEts, val)
  end
  # @printf("sampleTimePicoseconds: %d\n", sampleTimePicoseconds.x)
end

function getTimebase(handle::Ref{Cshort}, timebase::Int, noSamples::Int, timeIntervalNanoseconds::Ref{Clong}, oversample::Int, maxSamples::Ref{Clong}, segmentIndex::Int)
  val = ccall((GetTimebase, libname), Int32, (Cshort,Culong,Clong,Ref{Clong},Cshort,Ref{Clong}, Cushort), handle.x, timebase, noSamples, timeIntervalNanoseconds, oversample, maxSamples, segmentIndex)
  if val != 0
    @printf("error %s: %d\n", GetTimebase, val)
  end
end

function setDataBufferBulk(handle::Ref{Cshort}, channel::InputChannel, buffer::Vector{Int16}, waveform::Int)
  val = ccall((SetDataBufferBulk, libname), Int32, (Cshort,Clong,Ptr{Cshort},Clong, Culong), handle.x, channel, buffer, length(buffer)*2, waveform)
  if val != 0
    @printf("error %s: %d\n", SetDataBufferBulk, val)
  end
end

function getValuesBulk(handle::Ref{Cshort}, noOfSamples::Ref{Culong}, fromSegmentIndex::Int, toSegmentIndex::Int, overflow::Vector{UInt16})
  val = ccall((GetValuesBulk, libname), Int32, (Cshort,Ref{Culong},Cushort, Cushort, Ptr{Cushort}), handle.x, noOfSamples, fromSegmentIndex, toSegmentIndex, overflow)
  if val != 0
    @printf("error %s: 0x%02x\n", GetValuesBulk, val)
  end
end

function setNoOfCaptures(handle::Ref{Cshort}, nrCaptures::Int)
  val = ccall((SetNoOfCaptures, libname), Int32, (Cshort,Cushort), handle.x, nrCaptures)
  if val != 0
    @printf("error %s: %d\n", SetNoOfCaptures, val)
  end
end

function memorySegments(handle::Ref{Cshort}, nrSegments::Int, nMaxSamples::Ref{Clong})
  val = ccall((MemorySegments, libname), Int32, (Cshort,Cushort,Ref{Clong}), handle.x, nrSegments, nMaxSamples)
  if val != 0
    @printf("error %s: %d\n", MemorySegments, val)
  end
end

function setSimpleTrigger(handle::Ref{Cshort}, enabled::Bool, channel::InputChannel, threshold::Int, direction::ThresholdDirection, delay::Int, autotrigger_ms::Int)
  val = ccall((SetSimpleTrigger, libname), Int32, (Cshort,Cshort,Clong,Cshort,Clong,Culong,Cshort), handle.x, enabled ? 1:0, channel, threshold, direction, delay, autotrigger_ms)
  if val != 0
    @printf("error %s: %d\n", SetSimpleTrigger, val)
  end
end

function runBlock(handle::Ref{Cshort}, noOfPreTriggerSamples::Int, noOfPostTriggerSamples::Int, timebase::Int, oversample::Int, timeIndisposedMs::Ref{Culong}, segmentIndex::Int)
  val = ccall((RunBlock, libname), Int32, (Cshort,Clong,Clong,Culong,Cshort,Ref{Culong},Cushort,Ptr{Void},Ptr{Void}), handle.x, noOfPreTriggerSamples, noOfPostTriggerSamples, timebase, oversample, timeIndisposedMs, segmentIndex, C_NULL, C_NULL)
  if val != 0
    @printf("error %s: 0x%02x\n", RunBlock, val)
    closeUnit(handle)

  end
end

function isReady(handle::Ref{Cshort}, ready::Ref{Cshort})
  val = ccall((IsReady, libname), Int32, (Cshort,Ref{Cshort}), handle.x, ready)
  if val != 0
    @printf("error %s: %d\n", IsReady, val)
  end
end

function getValuesTriggerTimeOffsetBulk64(handle::Ref{Cshort}, times::Vector{Int64}, timeUnits::Vector{UInt32}, fromSegmentIndex::Int, toSegmentIndex::Int)
  val = ccall((GetValuesTriggerTimeOffsetBulk64, libname), Int32, (Cshort,Ptr{Int64},Ptr{UInt32},Cushort,Cushort), handle.x, times, timeUnits, fromSegmentIndex, toSegmentIndex)
  if val != 0
    @printf("error %s: %d\n", GetValuesTriggerTimeOffsetBulk64, val)
  end
end

function getTriggerTimeOffset64(handle::Ref{Cshort}, times::Vector{Int64}, timeUnits::Vector{UInt32}, segment::Int)
  val = ccall((GetTriggerTimeOffset64, libname), Int32, (Cshort,Ptr{Int64},Ptr{UInt32},Cushort,Cushort), handle.x, times, timeUnits, fromSegmentIndex, toSegmentIndex)
  if val != 0
    @printf("error %s: %d\n", GetTriggerTimeOffset64, val)
  end
end

function setSigGenBuiltIn(handle::Ref{Cshort}, offsetVoltage::Int, pkToPk::Int, waveType::Int, startFrequency::Float64, stopFrequency::Float64, increment::Float64, dwellTime::Float64, sweepType::Int, whiteNoise::Int,shots::Int,sweeps::Int,triggerType::Int,triggerSource::Int,extInThreshold::Int )
  val = ccall((SetSigGenBuiltIn, libname), Int32, (Cshort,Clong,Culong,Cshort,Cfloat,Cfloat,Cfloat,Cfloat,Cint,Cshort,Culong,Culong,Cint,Cint,Cshort), handle.x, offsetVoltage, pkToPk, waveType, startFrequency, stopFrequency, increment, dwellTime, sweepType, whiteNoise, shots, sweeps, triggerType, triggerSource, extInThreshold)
  if val != 0
    @printf("error %s: %d\n", SetSigGenBuiltIn, val)
  end
end

type Scope
  handle::Ref{Cshort}
  availableInputChannels::Vector{InputChannel}
  channels::Vector{InputChannel}
  timebase::Int
  preTriggerSamples::Int
  postTriggerSamples::Int
  acquisitions::Int
  blocks::Int
  maxBlocks::Int
  buffers::Vector{Vector{Int16}}
  triggerChannel::InputChannel

  function Scope()
    return new(Ref{Cshort}(0), [PS_CHANNEL_A, PS_CHANNEL_B], [PS_CHANNEL_A], 0, 100, 3200, 100, 1, 10, Vector{Vector{Int16}}(0), PS_CHANNEL_EXT)
  end
end

function setupScope(s::Scope)
  handle = s.handle
  availableInputChannels = s.availableInputChannels
  channels = s.channels
  timebase = s.timebase
  preTriggerSamples = s.preTriggerSamples
  postTriggerSamples = s.postTriggerSamples
  acquisitions = s.acquisitions

  openUnit(handle)

  setEts(handle, PS_ETS_OFF, 0, 0)
  for c in availableInputChannels
    if c in channels
      setChannel(handle, c, true, true, PS_500MV)
    else
      setChannel(handle, c, false, true, PS_5V)
    end
  end

  timeIntervalNanoseconds = Ref{Clong}(0)
  maxSamples = Ref{Clong}(0)
  getTimebase(handle,timebase, 1, timeIntervalNanoseconds, 0, maxSamples, 0)

  @printf("Scope says it has a buffer for %d samples\n", maxSamples.x)

  samples = preTriggerSamples + postTriggerSamples
  blocks = div(maxSamples.x, samples) - 10
  blocks = min(blocks, s.maxBlocks)

  @printf("Will get %d blocks per acquisition: %d blocks * %d acquisitions == %d traces of %d samples\n", blocks, blocks, acquisitions, blocks * acquisitions, samples)

  memorySegments(handle, blocks, maxSamples)
  setNoOfCaptures(handle, blocks)

  @printf("Scope says %d samples per segment are available\n", maxSamples.x)

  if maxSamples.x < samples
    @printf("BAD! Scope doesn't have enough samples available for this number of blocks, try lowering scope.maxBlocks!!!\n")
  end

  s.buffers = Vector{Vector{Int16}}(blocks * length(channels))

  for cidx in 1:length(channels)
    for b in 1:blocks
      s.buffers[b + (cidx-1)*blocks] = ones(Int16, samples)
      setDataBufferBulk(handle, channels[cidx], s.buffers[b + (cidx-1)*blocks], b-1)
    end
  end

  s.blocks = blocks

  setSimpleTrigger(handle, true, s.triggerChannel, 1000, RISING, 0, 1000)

  return s
end

function armScope(s::Scope)
  timeIndisposedMs = Ref{Culong}(0)
  runBlock(s.handle, s.preTriggerSamples, s.postTriggerSamples, s.timebase, 0, timeIndisposedMs, 1)
end

function fetchScopeData(s::Scope)
  ready = Ref{Cshort}(0)

  while ready.x == 0
    isReady(s.handle, ready)
  end

  # @printf("done runBLlok , scope timeIndisposedMs %d!\n", timeIndisposedMs.x)
  noOfSamples = Ref{Culong}(s.preTriggerSamples + s.postTriggerSamples)
  blocks = s.blocks
  overflow = ones(UInt16, blocks)
  times = ones(Int64, blocks)
  timeUnits = ones(UInt32, blocks)

  getValuesBulk(s.handle, noOfSamples, 0, s.blocks-1, overflow)
  # @printf("fetched data, noOfSamples %d, overflow %s\n", noOfSamples.x, string(overflow))

  getValuesTriggerTimeOffsetBulk64(s.handle, times, timeUnits, 0, s.blocks-1)
  # @printf("fetched times: %s\n", string(times))

end

function closeScope(scope::Scope)
  closeUnit(scope.handle)
end

getSamples(scope::Scope) = scope.preTriggerSamples + scope.postTriggerSamples

# TODO: feed this patch back into https://github.com/andrewadare/LibSerialPort.jl
function sp_blocking_read!(port::Port, buffer::Array{UInt8}, timeout_ms::Integer)

    # If the read succeeds, the return value is the number of bytes read.
    ret = ccall((:sp_blocking_read, "libserialport"), SPReturn,
                (Port, Ptr{UInt8}, Csize_t, Cuint),
                port, buffer, Csize_t(length(buffer)), Cuint(timeout_ms))
    handle_error(ret, loc())

    nb = Int(ret)
    if nb != length(buffer)
      @printf("serial timed out: %d expected %d!!!! bAD, you don't want to see this ever!\n", nb, length(buffer))
      throw(ErrorException("bad!"))
    end
    return nb
end

#  input gen for AES128 MC attack
function inputgenMC(rng)
    r = rand(rng, 1:4)
    return [(i in [o for o in r:4:16] ? UInt8(rand(rng, 0:255)) : 0x0) for i in 1:16]
end

# just all randoms, for sbox attack
function inputgenSB(rng)
    return [UInt8(rand(rng, 0:255)) for i in 1:16]
end

# semi constant AES128 sbox 5 state input generator
function input128TVLA(rng,expkey)
    state = zeros(UInt8, 16)
    state[rand(rng,1:16)] = (1 << rand(rng,0:7))
    state[rand(rng,1:16)] = (1 << rand(rng,0:7))
    rx_s_box = reshape(state, (4,4))

    # AES128 decrypt r6.istart == AES encrypt r5.sbox
    input = Aes.InvCipher(state, expkey, (label,state)-> "r6.istart" == label ? rx_s_box : state)

    return input
end

# This is the acquisition loop
function main()
  s = SerialPort("/dev/ttyUSB0")
  open(s)
  set_speed(s, 115200)
  set_frame(s, ndatabits=8, parity=SP_PARITY_NONE, nstopbits=1)
  set_flow_control(s)
  print_port_settings(s)

  flush(s, buffer=SP_BUF_BOTH)

  cmd::Vector{UInt8} = hex2bytes("CA000102030405060708090A0B0C0D0E0F")
  res::Vector{UInt8} = Vector{UInt8}(16)

  scope = Scope()
  scope.preTriggerSamples = 0
  scope.postTriggerSamples = 3000
  scope.timebase = 0
  scope.maxBlocks = 8*1024
  scope.acquisitions = 30
  scope.channels = [PS_CHANNEL_B]
  scope.triggerChannel = PS_CHANNEL_EXT
  setupScope(scope)

  data_fd = open("pipo2_data_33s.bin", "w")
  sample_fd = open(@sprintf("pipo2_samples_Int16_%ds.bin", getSamples(scope)), "w")

  rng = MersenneTwister(1)
  key = hex2bytes("cafebabedeadbeef0001020304050607")
  expkey = Aes.KeyExpansion(key, 10, 4)
  progress = Progress(scope.acquisitions * scope.blocks, 1, @sprintf("Acquiring %d traces ..", scope.acquisitions * scope.blocks))



  for a in 1:scope.acquisitions
    armScope(scope)

    for i in 1:scope.blocks
      coin::UInt8 = UInt8(rand(0:1))
      if coin == 0
        cmd[2:17] = inputgenMC(rng)
      else
        cmd[2:17] = input128TVLA(rng,expkey)
      end
      # @printf("=> %s\n", bytes2hex(cmd))
      sp_nonblocking_write(s.ref, cmd)
      update!(progress, (a-1)*scope.blocks + i)
      write(data_fd, coin)
      write(data_fd, cmd[2:17])

      sp_blocking_read!(s.ref, res, 1000)
      write(data_fd, res)
      # @printf("<= %s\n\n", bytes2hex(res))
    end

    fetchScopeData(scope)
    for i in 1:length(scope.buffers)
      write(sample_fd, scope.buffers[i])
    end

  end

  close(data_fd)
  close(sample_fd)
  closeScope(scope)
  close(s)

  return scope
end

# using PyPlot to do this
function plotSamples(scope::Scope)
  buffers = scope.buffers
  for i in 1:length(buffers)
    plot(buffers[i])
  end
end

# Some data I got from Inspector on how Pinata is driven and how long the trigger window is:
#  AES SW enc 215us
# > AE
# > 5E 70 B1 4C FD 0C A7 06 55 0C AB 4A F1 3B 39 73
# < 5F EB 91 62 28 88 09 72 4D 32 D5 1E BB B8 DF B9

# AES tables enc 19us
# > 41
# > 8F CA F8 3E C3 76 53 FC 49 93 E4 B3 44 6A 39 84
# < 3E A9 4B BB 0C E4 D9 EB 3C DC 03 AB A6 53 21 AB

# AES hw enc 3us
# > CA
# > 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
# < 7C 66 E0 D9 41 22 88 C6 5B AA 49 6F BA 54 83 FE
# >

#  Simple test for comms with the Pinata board
function hellopinata()
  s = SerialPort("/dev/ttyUSB0")
  open(s)
  set_speed(s, 115200)
  set_frame(s, ndatabits=8, parity=SP_PARITY_NONE, nstopbits=1)
  set_flow_control(s)
  print_port_settings(s)
  flush(s, buffer=SP_BUF_BOTH)

  cmd::Vector{UInt8} = hex2bytes("41000102030405060708090A0B0C0D0E0F")
  res::Vector{UInt8} = Vector{UInt8}(16)

  rng = MersenneTwister(1)

  iterations = 4000
  progress = Progress(iterations, 1, @sprintf("Running %d iterations ..", iterations))

  for a in 1:iterations
    cmd[2:17] = inputgenSB(rng)
    # @printf("=> %s\n", bytes2hex(cmd))
    sp_blocking_write(s.ref, cmd, 0)
    sp_blocking_read!(s.ref, res, 1000)
    # @printf("<= %s\n\n", bytes2hex(res))
    next!(progress)
  end

  finish!(progress)

  close(s)

end

# main or hellopinata is called here
@time scope = main()
# @time scope = hellopinata()
