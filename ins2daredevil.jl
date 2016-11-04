# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("conditional.jl")
include("trs.jl")

using Trs

function ins2daredevil(filename)
	trs = InspectorTrace(filename)
	(data,samples) = trs[1]

	guessesfn = @sprintf("data_%d_b_%d.bin", 8, length(trs))
	samplesfn = @sprintf("samples_%d_b_%d.bin", length(samples), length(trs))
	guesses = open(guessesfn, "w")
	samples = open(samplesfn, "w")

	for (data, sample) in trs
		write(guesses, data[9:16])
		write(samples, sample)
	end

	@printf("Daredevil config:\n")
	@printf("guess=%s %d %d\n", guessesfn, length(trs), length(trs[1][1]))
	@printf("trace=%s %d %d\n", samplesfn, length(trs), length(trs[1][2]))

	close(guesses)
	close(samples)
		# write(samples, reinterpret(UInt8, trace))

end

ins2daredevil(ARGS[1])
