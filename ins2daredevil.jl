# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("trs.jl")

using Trs

function ins2daredevil(filename)
	trs = InspectorTrace(filename)
	(data,samples) = trs[1]

	guessesfn = @sprintf("data_UInt8_%dt.bin", length(trs))
	samplesfn = @sprintf("samples_%s_%dt.bin", eltype(samples), length(trs))

	trs2 = SplitBinary(guessesfn, length(data), samplesfn, length(samples), eltype(samples), length(trs), true)

	for i in 1:length(trs)
		trs2[i] = trs[i]
	end


	@printf("Daredevil config:\n")
	@printf("guess=%s %d %d\n", guessesfn, length(trs), length(trs[1][1]))
	@printf("trace=%s %d %d\n", samplesfn, length(trs), length(trs[1][2]))

	close(trs)
	close(trs2)
end

ins2daredevil(ARGS[1])
