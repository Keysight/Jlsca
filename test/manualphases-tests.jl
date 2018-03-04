using Jlsca.Sca
using Jlsca.Trs

using Base.Test

function mytest() 
	fullfilename = "../shatraces/sha1_67452301efcdab8998badcfe10325476c3d2e1f0.trs"
    @printf("file: %s\n", fullfilename)

    params = getParameters(fullfilename, FORWARD)
    params.analysis = IncrementalCPA()
    params.analysis.leakages = [HW()]

    params.phases = [7,12,14]
    knownKey = get(params.knownKey)

    # create Trace instance
    trs = InspectorTrace(fullfilename)    

	# samples are intermediates, convert to "leakage" here.
  	addSamplePass(trs, x -> hw.(x))

  	setPostProcessor(trs, IncrementalCorrelation())

  	rankdata = sca(trs,params,1,100)

  	key = getKey(params, rankdata)

    @test(key == knownKey)

    params.knownKey = Nullable()
    params.phaseInput = hex2bytes("b398b49f0dcdb066000c0804010d0905e26af37b97563d")

  	rankdata = sca(trs,params,1,100)

  	key = getKey(params, rankdata)
    @test(key == knownKey)

    params.knownKey = Nullable()
    params.phaseInput = hex2bytes("000000000dcdb066000c0804010d0905e26af37b97563d")

  	rankdata = sca(trs,params,1,100)

  	key = getKey(params, rankdata)
    @test(key != knownKey)
end

function mytest2() 
	fullfilename = "../shatraces/sha1_67452301efcdab8998badcfe10325476c3d2e1f0.trs"
	# fullfilename = "../aestraces/aes192_sb_eqinvciph_5460adcd34117f1d9a90352d3a37188f6e9724f0696898d2.trs"
    @printf("file: %s\n", fullfilename)

    params = getParameters(fullfilename, FORWARD)
    params.analysis = IncrementalCPA()
    params.analysis.leakages = [HW()]
    knownKey = get(params.knownKey)

    # create Trace instance
    trs = InspectorTrace(fullfilename)    

	# samples are intermediates, convert to "leakage" here.
  	addSamplePass(trs, x -> hw.(x))

  	setPostProcessor(trs, IncrementalCorrelation())

  	rankdata = nothing

    params = getParameters(fullfilename, FORWARD)
    params.analysis = IncrementalCPA()
    params.analysis.leakages = [HW()]
    knownKey = get(params.knownKey)

  	for p in 1:numberOfPhases(params.attack)
  		params.phases = [p]

  		rd = sca(trs,params,1,100)
  		if rankdata == nothing
  			rankdata = rd
  		else
  			add!(rankdata,rd)
  		end
  	end

  	key = getKey(params, rankdata)

    @test(key == knownKey)

  	rankdata = nothing

    params = getParameters(fullfilename, FORWARD)
    params.analysis = IncrementalCPA()
    params.analysis.leakages = [HW()]
    knownKey = get(params.knownKey)
  	params.knownKey = Nullable()

  	for p in 1:numberOfPhases(params.attack)
  		params.phases = [p]

  		rd = sca(trs,params,1,100)
  		if rankdata == nothing
  			rankdata = rd
  		else
  			add!(rankdata,rd)
  		end
  	end

  	key = getKey(params, rankdata)

    @test(key == knownKey)
end

mytest2()
