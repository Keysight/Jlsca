# This file is part of Jlsca, license is GPLv3, see https://www.gnu.org/licenses/gpl-3.0.en.html
#
# Author: Cees-Bart Breunesse

module Sca

include("sca-leakages.jl")
include("sca-core.jl")
include("sca-scoring.jl")

include("dpa.jl")
include("lra.jl")
include("mia.jl")

include("attackaes-core.jl")
include("attackdes-core.jl")

include("incremental-correlation.jl")

end
