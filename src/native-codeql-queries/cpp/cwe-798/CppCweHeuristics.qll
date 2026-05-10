private import cpp

bindingset[text]
predicate credentialKeyword(string text) {
  exists(string lower |
    lower = text.toLowerCase() and
    (
      lower.matches("%password%")
      or lower.matches("%passwd%")
      or lower.matches("%pwd%")
      or lower.matches("%passphrase%")
      or lower.matches("%secret%")
      or lower.matches("%token%")
      or lower.matches("%api_key%")
      or lower.matches("%apikey%")
      or lower.matches("%access_key%")
      or lower.matches("%private_key%")
      or lower.matches("%credential%")
      or lower.matches("%authorization%")
      or lower.matches("%auth%")
      or lower.matches("%session%")
      or lower.matches("%cookie%")
    )
  )
}

bindingset[text]
predicate lowValueCredentialText(string text) {
  exists(string lower |
    lower = text.toLowerCase() and
    (
      lower = ""
      or lower = "password"
      or lower = "passwd"
      or lower = "secret"
      or lower = "token"
      or lower.matches("%example%")
      or lower.matches("%sample%")
      or lower.matches("%dummy%")
      or lower.matches("%test%")
      or lower.matches("%placeholder%")
      or lower.matches("%changeme%")
      or lower.matches("%change_me%")
      or lower.matches("%todo%")
      or lower.matches("%redacted%")
      or lower.matches("%masked%")
      or lower.matches("%xxxx%")
      or lower.matches("%****%")
    )
  )
}

bindingset[name]
predicate credentialName(string name) {
  credentialKeyword(name) and
  not name.toLowerCase().matches("%file%") and
  not name.toLowerCase().matches("%path%") and
  not name.toLowerCase().matches("%hash%") and
  not name.toLowerCase().matches("%crypt%")
}

predicate exprContains(Expr outer, Expr inner) {
  outer = inner
  or
  outer.getAChild*() = inner
}

predicate hardcodedString(Expr expr, string text) {
  exists(StringLiteral literal |
    exprContains(expr, literal) and
    text = literal.getValue() and
    text.length() > 5 and
    not lowValueCredentialText(text)
  )
}

bindingset[text]
predicate strongCredentialLiteral(string text) {
  not lowValueCredentialText(text) and
  (
    credentialKeyword(text) and text.length() > 8 and (text.matches("%=%") or text.matches("%:%"))
    or text.matches("%AKIA%")
    or text.matches("%AIza%")
    or text.matches("%xox%-%")
    or text.matches("%Bearer %")
    or text.matches("%Basic %")
    or text.matches("%-----BEGIN %PRIVATE KEY-----%")
    or text.regexpMatch("(?i).*(jdbc|mongodb|postgres|mysql)://[^\\s]*:[^\\s@]{6,}@.*")
  )
}

predicate containsCredentialVariable(Expr expr) {
  exists(VariableAccess access |
    exprContains(expr, access) and
    credentialName(access.getTarget().getName())
  )
}
