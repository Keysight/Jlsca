export Cond,add,get

abstract Cond

add(c::Cond, data::Vector, samples::Vector, idx::Int) = add(c, data, samples)
