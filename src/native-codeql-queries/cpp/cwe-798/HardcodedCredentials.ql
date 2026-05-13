/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id cpp/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-798
 */

import cpp
private import CppCweHeuristics

predicate hardcodedCredentialInitializer(Expr expr) {
  exists(Variable variable, string text |
    expr = variable.getInitializer().getExpr() and
    credentialName(variable.getName()) and
    hardcodedString(expr, text)
  )
}

predicate hardcodedByteArrayCredentialInitializer(Expr expr) {
  exists(Variable variable, ArrayAggregateLiteral literal, HexLiteral hex, string lowerName |
    expr = variable.getInitializer().getExpr() and
    expr = literal and
    lowerName = variable.getName().toLowerCase() and
    (
      credentialName(variable.getName())
      or
      lowerName = ["key", "aeskey", "secretkey", "encryptionkey", "cipherkey"]
    ) and
    literal.getAChild*() = hex
  )
}

predicate hardcodedCredentialAssignment(Expr expr) {
  exists(AssignExpr assign, VariableAccess target, string text |
    expr = assign.getRValue() and
    target = assign.getLValue() and
    credentialName(target.getTarget().getName()) and
    hardcodedString(expr, text)
  )
}

predicate credentialFunctionCallWithHardcodedArgument(FunctionCall call) {
  exists(Expr argument, int index, string text |
    credentialName(call.getTarget().getName()) and
    argument = call.getArgument(index) and
    hardcodedString(argument, text)
  )
}

predicate credentialComparisonWithHardcodedString(FunctionCall call) {
  exists(Expr left, Expr right, string text |
    call.getTarget().getName() = ["strcmp", "strncmp"] and
    left = call.getArgument(0) and
    right = call.getArgument(1) and
    (
      containsCredentialVariable(left) and hardcodedString(right, text)
      or
      hardcodedString(left, text) and containsCredentialVariable(right)
    )
  )
}

predicate standaloneCredentialLiteral(Expr expr) {
  exists(string text |
    hardcodedString(expr, text) and
    strongCredentialLiteral(text)
  )
}

class HardcodedCredentialFinding extends Expr {
  HardcodedCredentialFinding() {
    hardcodedCredentialInitializer(this)
    or
    hardcodedByteArrayCredentialInitializer(this)
    or
    hardcodedCredentialAssignment(this)
    or
    this instanceof FunctionCall and credentialFunctionCallWithHardcodedArgument(this.(FunctionCall))
    or
    this instanceof FunctionCall and credentialComparisonWithHardcodedString(this.(FunctionCall))
    or
    standaloneCredentialLiteral(this)
  }

  override string toString() { result = "hard-coded credential" }
}

from HardcodedCredentialFinding finding
select finding, "This hard-coded value is used as credentials."
