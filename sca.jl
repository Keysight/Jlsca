# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

include("aes.jl")
include("des.jl")
include("dpa.jl")
include("lra.jl")
include("mia.jl")
include("trs.jl")
include("align.jl")

module Sca

include("sca-core.jl")
include("sca-leakages.jl")
include("sca-scoring.jl")
include("attackaes-core.jl")
include("attackdes-core.jl")

end
