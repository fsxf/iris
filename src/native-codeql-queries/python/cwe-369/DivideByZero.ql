/**
 * @name Divide by zero
 * @description Division, floor division, or modulo by a value that can be zero.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id python/divide-by-zero
 * @tags security
 *       external/cwe/cwe-369
 */

import python

class DivisionOrModulo extends BinaryExpr {
  DivisionOrModulo() {
    this.getOp() instanceof Div or
    this.getOp() instanceof FloorDiv or
    this.getOp() instanceof Mod
  }

  Expr getDenominator() { result = this.getRight() }
}

predicate isZeroLiteral(Expr e) {
  e instanceof IntegerLiteral and e.(IntegerLiteral).getValue() = 0
  or
  e instanceof FloatLiteral and e.(FloatLiteral).getValue() = 0.0
}

predicate sameVariable(Expr a, Expr b) {
  a = b
  or
  exists(Name an, Name bn |
    a = an and
    b = bn and
    an.getVariable() = bn.getVariable()
  )
}

predicate isZeroExpr(Expr e) {
  isZeroLiteral(e)
  or
  exists(BinaryExpr bin |
    e = bin and
    bin.getOp() instanceof Sub and
    sameVariable(bin.getLeft(), bin.getRight())
  )
  or
  exists(BinaryExpr bin |
    e = bin and
    bin.getOp() instanceof Mult and
    (
      isZeroLiteral(bin.getLeft())
      or
      isZeroLiteral(bin.getRight())
    )
  )
}

predicate functionMayReturnZero(Function f) {
  exists(Return ret |
    ret.getScope() = f and
    isZeroExpr(ret.getValue())
  )
}

predicate callMayReturnZero(Expr e) {
  exists(Call call, Function f |
    e = call and
    call.getFunc().(Name).getId() = f.getName() and
    call.getScope().getEnclosingModule() = f.getEnclosingModule() and
    functionMayReturnZero(f)
  )
}

predicate simpleLocalAssignment(Name read, Expr source) {
  exists(Assign assign, Name target |
    assign.getATarget() = target and
    target.getVariable() = read.getVariable() and
    assign.getScope() = read.getScope() and
    assign.getValue() = source
  )
}

predicate mayBeZero(Expr e, string reason) {
  isZeroExpr(e) and reason = "the denominator is always zero"
  or
  callMayReturnZero(e) and reason = "the denominator is returned by a function that may return zero"
  or
  exists(Name read, Expr source |
    e = read and
    simpleLocalAssignment(read, source) and
    (
      isZeroExpr(source) and reason = "the denominator is assigned a value that is always zero"
      or
      callMayReturnZero(source) and
      reason = "the denominator is assigned a function return value that may be zero"
    )
  )
}

predicate nonZeroCondition(Expr condition, Expr denominator) {
  sameVariable(condition, denominator)
  or
  exists(Compare cmp |
    condition = cmp and
    cmp.getOp(0) instanceof NotEq and
    (
      sameVariable(cmp.getLeft(), denominator) and isZeroLiteral(cmp.getComparator(0))
      or
      isZeroLiteral(cmp.getLeft()) and sameVariable(cmp.getComparator(0), denominator)
    )
  )
  or
  exists(Compare cmp |
    condition = cmp and
    cmp.getOp(0) instanceof IsNot and
    (
      sameVariable(cmp.getLeft(), denominator) and isZeroLiteral(cmp.getComparator(0))
      or
      isZeroLiteral(cmp.getLeft()) and sameVariable(cmp.getComparator(0), denominator)
    )
  )
  or
  exists(BoolExpr bool |
    condition = bool and
    bool.getOp() instanceof And and
    nonZeroCondition(bool.getAValue(), denominator)
  )
}

predicate guardedNonZero(DivisionOrModulo div, Expr denominator) {
  exists(If ifStmt, Stmt guardedStmt |
    guardedStmt = ifStmt.getAStmt() and
    guardedStmt.contains(div) and
    nonZeroCondition(ifStmt.getTest(), denominator)
  )
  or
  exists(Assert assert |
    assert.getScope() = div.getScope() and
    assert.getLocation().getEndLine() < div.getLocation().getStartLine() and
    nonZeroCondition(assert.getTest(), denominator)
  )
}

from DivisionOrModulo div, Expr denominator, string reason
where
  denominator = div.getDenominator() and
  mayBeZero(denominator, reason) and
  not guardedNonZero(div, denominator)
select div, "This arithmetic operation can divide by zero because " + reason + "."
