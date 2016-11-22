
# data per row
function prepModAdd(idx::Int, key::UInt32, data::Array{UInt8})
	# big endian
	d::UInt32 = hton(reinterpret(UInt32, data)[1])

	# add the partial result and return the byte we're attacking
	ret::UInt8 = UInt8(((d + key) >> (idx*8)) & 0xff)

	return [ret]
end

function modaddout(data::Array{UInt8}, dataColumn, keyByte::UInt8)
	return data .+ keyByte
end

type ModAddAttack <: Attack
  knownKey::Nullable{Vector{UInt8}}
  analysis::Analysis
  updateInterval::Nullable{Int}
  phases::Vector{Phase}
  phaseInput::Nullable{Vector{UInt8}}
  outputkka::Nullable{AbstractString}

  function ModAddAttack()
  	return new(Nullable(), DPA(), Nullable(), [PHASE1], Nullable(), Nullable())
  end
end

function printParameters(params::ModAddAttack)
end

function scatask(trs::Trace, params::ModAddAttack, firstTrace=1, numberOfTraces=length(trs), phase::Phase=PHASE1, phaseInput=Nullable{Vector{UInt8}}())

	if phase == PHASE1
		partialKey = UInt32(0)
		idx = 0
	elseif phase == PHASE2
		partialKey = hton(reinterpret(UInt32, get(phaseInput))[1])
		idx = 1
	elseif phase == PHASE3
		partialKey = hton(reinterpret(UInt32, get(phaseInput))[1])
		idx = 2
	elseif phase == PHASE4
		partialKey = hton(reinterpret(UInt32, get(phaseInput))[1])
		idx = 3
	else
		throw(Error("aap"))
	end

	addDataPass(trs, x -> prepModAdd(idx, partialKey, x))
	# addDataPass(trs, x -> x[2] + (UInt16(x[1]) + 0xef > 0xff ? 0x1 : 0x0))

	targetFunction = modaddout
	dataWidth = 1

	scores = analysis(params, phase, trs, firstTrace, numberOfTraces, targetFunction, UInt8, collect(UInt8, 0:255), collect(1:dataWidth))

	rk = getRoundKey(scores)

	popDataPass(trs)

	if phase == PHASE1
		tmp = zeros(UInt8, 4)
		tmp[4] = rk[1]
		produce(PHASERESULT, Nullable(tmp))
	elseif phase == PHASE2
		tmp = get(phaseInput)
		tmp[3] = rk[1]
		produce(PHASERESULT, phaseInput)
	elseif phase == PHASE3
		tmp = get(phaseInput)
		tmp[2] = rk[1]
		produce(PHASERESULT, phaseInput)
	elseif phase == PHASE4
		tmp = get(phaseInput)
		tmp[1] = rk[1]
		produce(PHASERESULT, phaseInput)
	else
		throw(Error("aap"))
	end



end

function getNumberOfAverages(params::ModAddAttack)
	return 256
end

function shattack()
  # read Inspector traces from stdin
  trs = InspectorTrace(ARGS[1])

  params = ModAddAttack()

  params.analysis = DPA()
  # params.analysis.postProcess = Nullable()
  params.analysis.leakageFunctions = [hw]
  # params.analysis.leakageFunctions = [hw; [x -> ((x .>> i) & 1) for i in 0:7 ]]
  # params.analysis.leakageFunctions = [x -> ((x .>> i) & 1) for i in 0:7 ]

  # params.analysis = LRA()

  params.phases = [PHASE1, PHASE2, PHASE3, PHASE4]
  # params.analysis.leakageFunctions = [hw]

  # enable conditional averaging
  # setPostProcessor(trs, CondAvg, getNumberOfAverages(params))

  # addSamplePass(trs, x -> x[1:8])

  # go baby go!
  return sca(trs, params, 1, length(trs), false)

end
