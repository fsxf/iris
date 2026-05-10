/**
 * @name Divide by zero
 * @description Division or remainder by a value that can be zero.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/divide-by-zero
 * @tags security
 *       external/cwe/cwe-369
 */

import java
private import semmle.code.java.controlflow.Guards
private import semmle.code.java.dataflow.IntegerGuards

class DivisionOrRemainder extends Expr {
  DivisionOrRemainder() {
    this instanceof DivExpr or
    this instanceof RemExpr or
    this instanceof AssignDivExpr or
    this instanceof AssignRemExpr
  }

  Expr getDenominator() {
    result = this.(DivExpr).getRightOperand()
    or
    result = this.(RemExpr).getRightOperand()
    or
    result = this.(AssignDivExpr).getRhs()
    or
    result = this.(AssignRemExpr).getRhs()
  }
}

predicate isZeroLiteral(Expr e) {
  e.getUnderlyingExpr().(CompileTimeConstantExpr).getIntValue() = 0
}

predicate isZeroExpr(Expr e) {
  isZeroLiteral(e)
  or
  exists(SubExpr sub |
    e.getUnderlyingExpr() = sub and
    sub.getLeftOperand().toString() = sub.getRightOperand().toString()
  )
  or
  exists(MulExpr mul |
    e.getUnderlyingExpr() = mul and
    (
      isZeroLiteral(mul.getLeftOperand())
      or
      isZeroLiteral(mul.getRightOperand())
    )
  )
}

predicate methodMayReturnZero(Method m) {
  exists(ReturnStmt ret |
    ret.getEnclosingCallable() = m and
    isZeroExpr(ret.getResult())
  )
}

predicate callMayReturnZero(Expr e) {
  exists(MethodCall call, Method target |
    e.getUnderlyingExpr() = call and
    call.getCallee() = target and
    methodMayReturnZero(target)
  )
}

predicate simpleLocalAssignment(VarRead read, Expr source) {
  exists(VariableAssign assign |
    assign.getDestVar() = read.getVariable() and
    assign.getSource() = source and
    assign.getEnclosingCallable() = read.getEnclosingCallable()
  )
}

predicate mayBeZero(Expr e, string reason) {
  isZeroExpr(e) and reason = "the denominator is always zero"
  or
  callMayReturnZero(e) and reason = "the denominator is returned by a method that may return zero"
  or
  exists(VarRead read |
    e.getUnderlyingExpr() = read and
    read.getVariable() instanceof Parameter and
    read.getVariable().getName().regexpMatch("(?i).*(denom|divisor|count|size|length|num|total|limit|page|rate|width|height).*") and
    reason = "the denominator comes from a parameter that is not checked for zero"
  )
  or
  exists(VarRead read, Expr source |
    e.getUnderlyingExpr() = read and
    (
      simpleLocalAssignment(read, source)
      or
      read.getVariable().getAnAssignedValue() = source
    ) and
    (
      isZeroExpr(source) and reason = "the denominator is assigned a value that is always zero"
      or
      callMayReturnZero(source) and
      reason = "the denominator is assigned a method return value that may be zero"
    )
  )
}

predicate guardedNonZero(DivisionOrRemainder div, Expr denominator) {
  exists(ConditionBlock cond, boolean branch |
    cond.getCondition() = nonZeroGuard(denominator.getUnderlyingExpr(), branch) and
    cond.controls(div.getBasicBlock(), branch)
  )
}

from DivisionOrRemainder div, Expr denominator, string reason
where
  denominator = div.getDenominator() and
  mayBeZero(denominator, reason) and
  not guardedNonZero(div, denominator)
select div, "This arithmetic operation can divide by zero because " + reason + "."
