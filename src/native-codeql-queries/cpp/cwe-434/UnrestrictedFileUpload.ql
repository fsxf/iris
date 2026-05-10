/**
 * @name Narrow unrestricted file upload to disk
 * @description Data returned by explicit upload or multipart APIs is used as a file-system write destination.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id cpp/unrestricted-file-upload
 * @tags security
 *       external/cwe/cwe-434
 */

import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.ir.dataflow.TaintTracking
private import CppCweHeuristics

predicate uploadApiCall(FunctionCall call) {
  explicitUploadApiName(call.getTarget().getName())
}

predicate variableAssignedFromUpload(Variable variable) {
  exists(Expr assigned, FunctionCall uploadCall |
    assigned = variable.getAnAssignedValue() and
    exprContains(assigned, uploadCall) and
    uploadApiCall(uploadCall)
  )
}

predicate expressionContainsUploadValue(Expr expr) {
  exists(FunctionCall uploadCall |
    exprContains(expr, uploadCall) and
    uploadApiCall(uploadCall)
  )
  or
  exists(VariableAccess access |
    exprContains(expr, access) and
    variableAssignedFromUpload(access.getTarget())
  )
}

predicate hasNearbyStrongControl(FunctionCall call, Expr destination) {
  exists(FunctionCall controlCall |
    strongUploadControlName(controlCall.getTarget().getName()) and
    controlCall != call and
    exprContains(controlCall, destination)
  )
}

predicate diskWriteUsesUploadValue(FunctionCall call) {
  exists(Expr argument |
    explicitDiskWriteName(call.getTarget().getName()) and
    argument = call.getArgument(0) and
    expressionContainsUploadValue(argument) and
    not hasNearbyStrongControl(call, argument)
  )
}

predicate isUploadSource(DataFlow::Node source) {
  exists(FunctionCall uploadCall |
    uploadApiCall(uploadCall) and
    DataFlow::exprNode(uploadCall) = source
  )
}

predicate isUploadDiskWriteSink(DataFlow::Node sink) {
  exists(FunctionCall call, Expr argument |
    explicitDiskWriteName(call.getTarget().getName()) and
    argument = call.getArgument(0) and
    not hasNearbyStrongControl(call, argument) and
    DataFlow::exprNode(argument) = sink
  )
}

module UploadToDiskConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    isUploadSource(source)
  }

  predicate isSink(DataFlow::Node sink) {
    isUploadDiskWriteSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    none()
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UploadToDiskFlow = TaintTracking::Global<UploadToDiskConfig>;

import UploadToDiskFlow::PathGraph

from UploadToDiskFlow::PathNode source, UploadToDiskFlow::PathNode sink
where
  UploadToDiskFlow::flowPath(source, sink) and
  exists(FunctionCall call |
    diskWriteUsesUploadValue(call) and
    call.getArgument(0) = sink.getNode().asExpr()
  )
select sink.getNode(), source, sink,
  "Data returned by an explicit upload API reaches this file write destination."
