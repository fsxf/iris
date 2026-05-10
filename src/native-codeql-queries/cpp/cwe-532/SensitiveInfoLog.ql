/**
 * @name Insertion of sensitive information into log files
 * @description Writing sensitive information to log files can expose it to an attacker.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id cpp/sensitive-log
 * @tags security
 *       external/cwe/cwe-532
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.ir.dataflow.TaintTracking
private import CppCweHeuristics

bindingset[name]
predicate loggingFunctionName(string name) {
  name.toLowerCase() =
    [
      "syslog", "log", "logger", "log_info", "log_error", "log_warn", "log_debug",
      "debug", "info", "warn", "warning", "error", "trace", "fatal", "critical"
    ]
  or
  name.toLowerCase().regexpMatch(".*(log|debug|info|warn|error|fatal|trace).*")
}

predicate isNamedLoggingCall(FunctionCall call) {
  loggingFunctionName(call.getTarget().getName())
}

predicate isLogFileHandle(Expr expr) {
  exists(VariableAccess access |
    exprContains(expr, access) and
    access.getTarget().getName().toLowerCase().matches("%log%")
  )
}

predicate isFileLoggingCall(FunctionCall call) {
  exists(Expr fileArg |
    call.getTarget().getName() = ["fprintf", "fputs", "fwrite"] and
    fileArg = call.getArgument(0) and
    isLogFileHandle(fileArg)
  )
}

predicate hasSensitiveArgument(FunctionCall call) {
  exists(Expr argument, int index |
    argument = call.getArgument(index) and
    (
      containsSensitiveVariable(argument)
      or
      containsSensitiveLiteral(argument)
    ) and
    (
      not isFileLoggingCall(call)
      or
      index > 0
    )
  )
}

predicate isSensitiveSource(DataFlow::Node source) {
  exists(VariableAccess access |
    containsSensitiveVariable(access) and
    DataFlow::exprNode(access) = source
  )
  or
  exists(StringLiteral literal |
    containsSensitiveLiteral(literal) and
    DataFlow::exprNode(literal) = source
  )
}

predicate isSensitiveLoggingSink(DataFlow::Node sink) {
  exists(FunctionCall call, Expr argument, int index |
    (
      isNamedLoggingCall(call)
      or
      isFileLoggingCall(call)
    ) and
    argument = call.getArgument(index) and
    (
      not isFileLoggingCall(call)
      or
      index > 0
    ) and
    DataFlow::exprNode(argument) = sink
  )
}

module SensitiveInfoLogConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isSensitiveSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isSensitiveLoggingSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    none()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module SensitiveInfoLogFlow = TaintTracking::Global<SensitiveInfoLogConfig>;

import SensitiveInfoLogFlow::PathGraph

from SensitiveInfoLogFlow::PathNode source, SensitiveInfoLogFlow::PathNode sink
where
  SensitiveInfoLogFlow::flowPath(source, sink) and
  exists(FunctionCall call, Expr argument, int index |
    (
      isNamedLoggingCall(call)
      or
      isFileLoggingCall(call)
    ) and
    hasSensitiveArgument(call) and
    argument = call.getArgument(index) and
    (
      not isFileLoggingCall(call)
      or
      index > 0
    ) and
    argument = sink.getNode().asExpr()
  )
select sink.getNode(), source, sink,
  "This logging call may write sensitive information."
