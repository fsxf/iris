private import cpp

bindingset[text]
predicate sensitiveKeyword(string text) {
  exists(string lower |
    lower = text.toLowerCase() and
    (
      lower.matches("%password%")
      or lower.matches("%passwd%")
      or lower.matches("%pwd%")
      or lower.matches("%secret%")
      or lower.matches("%token%")
      or lower.matches("%api_key%")
      or lower.matches("%apikey%")
      or lower.matches("%credential%")
      or lower.matches("%authorization%")
      or lower.matches("%auth%")
      or lower.matches("%session%")
      or lower.matches("%cookie%")
    )
  )
}

bindingset[text]
predicate lowValueSensitiveText(string text) {
  exists(string lower |
    lower = text.toLowerCase() and
    (
      lower.matches("%masked%")
      or lower.matches("%redacted%")
      or lower.matches("%example%")
      or lower.matches("%dummy%")
      or lower.matches("%sample%")
      or lower.matches("%test%")
      or lower.matches("%placeholder%")
      or lower.matches("%xxxx%")
      or lower.matches("%****%")
      or lower.matches("%hash%")
      or lower.matches("%hashed%")
      or lower.matches("%crypt%")
    )
  )
}

predicate exprContains(Expr outer, Expr inner) {
  outer = inner
  or
  outer.getAChild*() = inner
}

predicate containsSensitiveVariable(Expr expr) {
  exists(VariableAccess access, Variable variable, string name |
    exprContains(expr, access) and
    variable = access.getTarget() and
    name = variable.getName() and
    sensitiveKeyword(name) and
    not lowValueSensitiveText(name) and
    not name.toLowerCase().matches("%file%") and
    not name.toLowerCase().matches("%path%")
  )
}

bindingset[text]
predicate likelySecretLiteral(string text) {
  sensitiveKeyword(text) and
  text.length() > 10 and
  not lowValueSensitiveText(text) and
  (
    text.matches("%=%")
    or text.matches("%:%")
    or text.matches("%Bearer %")
    or text.matches("%Basic %")
    or text.matches("%AKIA%")
    or text.matches("%-----BEGIN %")
  )
}

predicate containsSensitiveLiteral(Expr expr) {
  exists(StringLiteral literal |
    exprContains(expr, literal) and
    likelySecretLiteral(literal.getValue())
  )
}
