
# fills the attack parameters with data from the file name
function getParameters(filename::AbstractString, direction::Direction)
  local params::DpaAttack
  local attack::Attack

  m = match(r"aes([0-9]+)_(..)_([^_]*)_([a-zA-Z0-9]*)", filename)
  if m != nothing
    if m.captures[2] == "sb"
      attack = AesSboxAttack()
      analysis = CPA()
      analysis.leakages = [Bit(i) for i in 0:7]
      params = DpaAttack(attack, analysis)
    elseif m.captures[2] == "mc"
      attack = AesMCAttack()
      analysis = CPA()
      params = DpaAttack(attack, analysis)
      params.analysis.leakages = [Bit(i) for i in 0:31]
    end
    attack.keyLength::AesKeyLength = div(parse(m.captures[1]),8)
    modeStr = m.captures[3]
    if modeStr == "ciph"
      attack.mode = CIPHER
    elseif modeStr == "invciph"
      attack.mode = INVCIPHER
    elseif modeStr == "eqinvciph"
      attack.mode = EQINVCIPHER
    end

    params.knownKey = hex2bytes(m.captures[4])
    attack.direction = direction

    if direction == FORWARD
      params.dataOffset = 1
    else
      params.dataOffset = 17
    end
    return params
  end

  m = match(r"([t]{0,1}des[1-3]{0,1})_([^_]*)_([a-zA-Z0-9]*)", filename)
  if m != nothing
    attack = DesRoundAttack()
    analysis = CPA()
    analysis.leakages = [HW()]
    params = DpaAttack(attack, analysis)
    modeStr = m.captures[1]
    if modeStr == "des"
      attack.mode = DES
    elseif modeStr == "tdes1"
      attack.mode = TDES1
    elseif modeStr == "tdes2"
      attack.mode = TDES2
    elseif modeStr == "tdes3"
      attack.mode = TDES3
    end

    attack.encrypt = (m.captures[2] == "enc" ? true : false)

    params.knownKey = hex2bytes(m.captures[3])
    attack.direction = direction
    if direction == FORWARD
      params.dataOffset = 1
    else
      params.dataOffset = 9
    end
    return params
  end

  m = match(r"sha1_([a-zA-Z0-9]{40})", filename)
  if m != nothing
    if direction == FORWARD
      attack = Sha1InputAttack()
      analysis = CPA()
      analysis.leakages = [HW()]
      params = DpaAttack(attack,analysis)
      params.dataOffset = 1
    else
      attack = Sha1OutputAttack()
      analysis = CPA()
      analysis.leakages = [HW()]
      params = DpaAttack(attack,analysis)
      params.dataOffset = 17
    end
    params.knownKey = hex2bytes(m.captures[1])
    return params
  end
end
