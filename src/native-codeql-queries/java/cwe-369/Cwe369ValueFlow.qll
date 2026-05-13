import java
private import semmle.code.java.controlflow.Guards
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.IntegerGuards
private import semmle.code.java.controlflow.UnreachableBlocks

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

predicate sameValueExpr(Expr left, Expr right) {
  left.getUnderlyingExpr() = right.getUnderlyingExpr()
  or
  exists(VarRead leftRead, VarRead rightRead |
    left.getUnderlyingExpr() = leftRead and
    right.getUnderlyingExpr() = rightRead and
    leftRead.getVariable() = rightRead.getVariable()
  )
}

predicate isZeroExpr(Expr e) {
  not staticallyUnreachableExpr(e) and
  (
    isZeroLiteral(e)
    or
    exists(SubExpr sub |
      e.getUnderlyingExpr() = sub and
      sameValueExpr(sub.getLeftOperand(), sub.getRightOperand())
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
  )
}

predicate isTrueBooleanConstant(Expr e) {
  e.getUnderlyingExpr().(CompileTimeConstantExpr).getBooleanValue() = true
  or
  exists(VarRead read |
    e.getUnderlyingExpr() = read and
    read.getVariable().isFinal() and
    isTrueBooleanConstant(read.getVariable().getInitializer())
  )
}

predicate isFalseBooleanConstant(Expr e) {
  e.getUnderlyingExpr().(CompileTimeConstantExpr).getBooleanValue() = false
  or
  exists(VarRead read |
    e.getUnderlyingExpr() = read and
    read.getVariable().isFinal() and
    isFalseBooleanConstant(read.getVariable().getInitializer())
  )
}

predicate staticallyUnreachableExpr(Expr e) {
  e instanceof UnreachableExpr
  or
  exists(ConditionBlock cond, boolean branch |
    cond.controls(e.getBasicBlock(), branch) and
    (
      branch = true and isFalseBooleanConstant(cond.getCondition())
      or
      branch = false and isTrueBooleanConstant(cond.getCondition())
    )
  )
}

predicate constantString(Expr e, string value) {
  e.getUnderlyingExpr().(CompileTimeConstantExpr).getStringValue() = value
  or
  exists(MethodCall trim |
    e.getUnderlyingExpr() = trim and
    trim.getMethod().getName() = "trim" and
    constantString(trim.getQualifier(), value)
  )
}

predicate stringLooksNonZeroNumber(string value) {
  value = ["1", "2", "3", "10", "100", "-1", "-2"]
}

predicate parseOrValueOfKnownNonZero(MethodCall call) {
  exists(Method target, string value |
    call.getCallee() = target and
    (
      isIntegerParseMethod(target)
      or
      isIntegerValueOfMethod(target)
    ) and
    hasStringArgument(call) and
    constantString(call.getArgument(0), value) and
    stringLooksNonZeroNumber(value)
  )
}

predicate numericExternalSourceCall(MethodCall call) {
  exists(Method target |
    call.getCallee() = target and
    (
      (
        isIntegerParseMethod(target)
        or
        isIntegerValueOfMethod(target)
      ) and
      hasStringArgument(call) and
      not parseOrValueOfKnownNonZero(call)
      or
      target.hasQualifiedName("java.util", "Scanner",
        ["nextInt", "nextLong", "nextShort", "nextByte"])
    )
  )
}

predicate isIntegerParseMethod(Method target) {
  target.hasQualifiedName("java.lang", ["Integer", "Long", "Short", "Byte"],
    ["parseInt", "parseLong", "parseShort", "parseByte"])
}

predicate isIntegerValueOfMethod(Method target) {
  target.hasQualifiedName("java.lang", ["Integer", "Long", "Short", "Byte"], "valueOf")
}

predicate hasStringArgument(MethodCall call) {
  call.getArgument(0).getType().(RefType).hasQualifiedName("java.lang", "String")
}

predicate reachableReturn(ReturnStmt ret, Method m) {
  ret.getEnclosingCallable() = m and
  exists(ret.getResult()) and
  not staticallyUnreachableExpr(ret.getResult())
}

predicate methodMayReturnZero(Method m) {
  exists(ReturnStmt ret |
    reachableReturn(ret, m) and
    isZeroExpr(ret.getResult())
  ) and
  forall(ReturnStmt ret |
    reachableReturn(ret, m)
  |
    isZeroExpr(ret.getResult())
  )
}

predicate callMayReturnZero(MethodCall call) {
  call.getCallee() = any(Method m | methodMayReturnZero(m))
}

predicate mayBeZeroSourceExpr(Expr e) {
  isZeroExpr(e)
  or
  e.getUnderlyingExpr() = any(MethodCall call | numericExternalSourceCall(call))
  or
  e.getUnderlyingExpr() = any(MethodCall call | callMayReturnZero(call))
}

predicate mathAbsOf(Expr absExpr, Expr guarded) {
  exists(MethodCall call |
    absExpr.getUnderlyingExpr() = call and
    call.getCallee().hasQualifiedName("java.lang", "Math", "abs") and
    sameValueExpr(call.getArgument(0), guarded)
  )
}

predicate mathAbsNonZeroGuard(Expr condition, Expr guarded, boolean branch) {
  exists(GreaterThanComparison cmp |
    condition.getUnderlyingExpr() = cmp and
    branch = true and
    mathAbsOf(cmp.getGreaterOperand(), guarded) and
    not isZeroExpr(cmp.getLesserOperand())
  )
}

predicate notEqualZeroGuard(Expr condition, Expr guarded, boolean branch) {
  exists(NEExpr cmp |
    condition.getUnderlyingExpr() = cmp and
    branch = true and
    (
      sameValueExpr(cmp.getLeftOperand(), guarded) and isZeroExpr(cmp.getRightOperand())
      or
      sameValueExpr(cmp.getRightOperand(), guarded) and isZeroExpr(cmp.getLeftOperand())
    )
  )
}

predicate positiveOrNegativeComparison(Expr condition, Expr guarded, boolean branch) {
  exists(GreaterThanComparison gt, LessThanComparison lt |
    condition.getUnderlyingExpr().(OrLogicalExpr).getLeftOperand() = gt and
    condition.getUnderlyingExpr().(OrLogicalExpr).getRightOperand() = lt and
    branch = true and
    (
      sameValueExpr(gt.getGreaterOperand(), guarded) and isZeroExpr(gt.getLesserOperand()) and
      sameValueExpr(lt.getLesserOperand(), guarded) and isZeroExpr(lt.getGreaterOperand())
      or
      sameValueExpr(gt.getGreaterOperand(), guarded) and isZeroExpr(gt.getLesserOperand()) and
      sameValueExpr(lt.getGreaterOperand(), guarded) and isZeroExpr(lt.getLesserOperand())
    )
  )
}

predicate explicitlyNonZeroGuard(Expr condition, Expr guarded, boolean branch) {
  condition = nonZeroGuard(guarded.getUnderlyingExpr(), branch)
  or
  notEqualZeroGuard(condition, guarded, branch)
  or
  mathAbsNonZeroGuard(condition, guarded, branch)
  or
  positiveOrNegativeComparison(condition, guarded, branch)
}

predicate guardedValueFlowToUse(Expr guarded, Expr use) {
  sameValueExpr(guarded, use)
  or
  guarded.getEnclosingCallable() = use.getEnclosingCallable() and
  DataFlow::localExprFlow(guarded, use)
}

predicate protectedByNonZeroGuard(Expr use) {
  exists(ConditionBlock cond, boolean branch, Expr guarded |
    cond.controls(use.getBasicBlock(), branch) and
    explicitlyNonZeroGuard(cond.getCondition(), guarded, branch) and
    guardedValueFlowToUse(guarded, use)
  )
}

predicate protectedDenominator(DivisionOrRemainder div) {
  protectedByNonZeroGuard(div.getDenominator())
}

predicate denominatorSinkExpr(Expr e) {
  e = any(DivisionOrRemainder div).getDenominator() and
  isIntegerDivisionDenominator(e)
}

predicate isIntegerDivisionDenominator(Expr e) {
  exists(Type t |
    e.getType() = t and
    isIntegerNumericType(t)
  )
}

predicate isIntegerNumericType(Type t) {
  exists(string name |
    name = [t.(PrimitiveType).getName(), t.(BoxedType).getPrimitiveType().getName()]
  |
    name = ["byte", "short", "int", "long"]
  )
}

module MayZeroConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Expr e |
      source.asExpr() = e and
      mayBeZeroSourceExpr(e)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(Expr e |
      sink.asExpr() = e and
      denominatorSinkExpr(e)
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    node.getType() instanceof BooleanType
    or
    exists(Expr e |
      node.asExpr() = e and
      protectedByNonZeroGuard(e)
    )
  }

  predicate isBarrierIn(DataFlow::Node node) { isSource(node) }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module MayZeroFlow = DataFlow::Global<MayZeroConfig>;
