/**
 * @name Unrestricted file upload to disk
 * @description Uploaded content or uploaded file names are written to disk without strong file type, file name, and destination controls.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id java/unrestricted-file-upload
 * @tags security
 *       external/cwe/cwe-434
 */

import java
private import semmle.code.java.dataflow.DataFlow
private import semmle.code.java.dataflow.TaintTracking
import UploadFlow::PathGraph

predicate isUploadType(Type t) {
  exists(RefType r | r = t |
    r.hasQualifiedName("org.springframework.web.multipart", "MultipartFile")
    or
    r.hasQualifiedName("javax.servlet.http", "Part")
    or
    r.hasQualifiedName("jakarta.servlet.http", "Part")
    or
    r.hasQualifiedName("org.apache.commons.fileupload", "FileItem")
    or
    r.hasQualifiedName("org.apache.commons.fileupload2.core", "FileItem")
  )
}

predicate isUploadObject(Expr e) {
  isUploadType(e.getType())
}

predicate isUploadGetter(MethodCall call) {
  exists(Expr qualifier |
    qualifier = call.getQualifier() and
    isUploadObject(qualifier) and
    call.getMethod().hasName([
        "getOriginalFilename", "getSubmittedFileName", "getName", "getInputStream", "getBytes",
        "get", "openStream"
      ])
  )
}

predicate isUploadSource(DataFlow::Node source) {
  exists(Expr e | source.asExpr() = e and isUploadObject(e))
  or
  exists(MethodCall call | source.asExpr() = call and isUploadGetter(call))
}

predicate isFilesMethod(MethodCall call, string name) {
  call.getMethod().hasName(name) and
  call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files")
}

predicate isDiskWriteSinkExpr(Expr e) {
  exists(MethodCall call |
    call.getMethod().hasName("transferTo") and
    isUploadObject(call.getQualifier()) and
    e = call.getQualifier()
  )
  or
  exists(MethodCall call |
    call.getMethod().hasName("write") and
    isUploadObject(call.getQualifier()) and
    (
      e = call.getQualifier()
      or
      e = call.getArgument(0)
    )
  )
  or
  exists(MethodCall call |
    isFilesMethod(call, ["copy", "write", "writeString", "newOutputStream"]) and
    (
      e = call.getArgument(0)
      or
      e = call.getArgument(1)
    )
  )
  or
  exists(MethodCall call |
    call.getMethod().hasName(["copyInputStreamToFile", "writeByteArrayToFile", "writeStringToFile"]) and
    call.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    e = call.getArgument(1)
  )
  or
  exists(ClassInstanceExpr output |
    output.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
    e = output.getArgument(0)
  )
}

predicate diskWriteDestinationForSink(Expr sink, Expr destination) {
  exists(MethodCall call |
    call.getMethod().hasName("transferTo") and
    isUploadObject(call.getQualifier()) and
    sink = call.getQualifier() and
    destination = call.getArgument(0)
  )
  or
  exists(MethodCall call |
    call.getMethod().hasName("write") and
    isUploadObject(call.getQualifier()) and
    (
      sink = call.getQualifier()
      or
      sink = call.getArgument(0)
    ) and
    destination = call.getArgument(0)
  )
  or
  exists(MethodCall call |
    isFilesMethod(call, ["write", "writeString", "newOutputStream"]) and
    (
      sink = call.getArgument(0)
      or
      sink = call.getArgument(1)
    ) and
    destination = call.getArgument(0)
  )
  or
  exists(MethodCall call |
    isFilesMethod(call, "copy") and
    (
      sink = call.getArgument(0)
      or
      sink = call.getArgument(1)
    ) and
    destination = call.getArgument(1)
  )
  or
  exists(MethodCall call |
    call.getMethod().hasName(["copyInputStreamToFile", "writeByteArrayToFile", "writeStringToFile"]) and
    call.getMethod().getDeclaringType().hasQualifiedName("org.apache.commons.io", "FileUtils") and
    sink = call.getArgument(1) and
    destination = call.getArgument(1)
  )
  or
  exists(ClassInstanceExpr output |
    output.getConstructedType().hasQualifiedName("java.io", "FileOutputStream") and
    sink = output.getArgument(0) and
    destination = output.getArgument(0)
  )
}

predicate exprContains(Expr parent, Expr child) {
  child = parent
  or
  child = parent.getAChildExpr+()
}

predicate variableAssignedFrom(Variable v, Expr source, Callable c) {
  exists(VariableAssign assign |
    assign.getDestVar() = v and
    assign.getSource() = source and
    assign.getEnclosingCallable() = c
  )
}

predicate exprUsesServerControlledFileName(Expr sink, Callable c) {
  exists(MethodCall call |
    call.getEnclosingCallable() = c and
    (
      call.getMethod().hasName(["randomUUID", "createTempFile", "createTempDirectory"])
      or
      call.getMethod().getDeclaringType().hasQualifiedName("java.nio.file", "Files") and
      call.getMethod().hasName(["createTempFile", "createTempDirectory"])
    ) and
    (
      exprContains(sink, call)
      or
      exists(VarRead read, Expr source |
        exprContains(sink, read) and
        variableAssignedFrom(read.getVariable(), source, c) and
        exprContains(source, call)
      )
    )
  )
}

predicate hasDestinationContainmentCheck(Expr sink, Callable c) {
  exists(MethodCall call |
    call.getEnclosingCallable() = c and
    call.getMethod().hasName(["startsWith", "getCanonicalPath", "toRealPath", "normalize"]) and
    (
      exprContains(call, sink)
      or
      exists(VarRead read, Expr source |
        exprContains(call, read) and
        variableAssignedFrom(read.getVariable(), source, c) and
        (
          exprContains(source, sink)
          or
          exprContains(sink, read)
        )
      )
      or
      call.getMethod().hasName(["getCanonicalPath", "toRealPath", "normalize"])
    )
  )
}

predicate hasContentMagicCheck(Callable c) {
  exists(MethodCall read |
    read.getEnclosingCallable() = c and
    read.getMethod().hasName(["read", "readNBytes", "getBytes"])
  ) and
  exists(ArrayAccess access, EqualityTest check |
    access.getEnclosingCallable() = c and
    check.getEnclosingCallable() = c and
    check.getAnOperand() = access
  )
}

predicate hasStrongUploadControls(Expr sink) {
  exists(Callable c, Expr destination |
    c = sink.getEnclosingCallable() and
    diskWriteDestinationForSink(sink, destination) and
    exprUsesServerControlledFileName(destination, c) and
    hasDestinationContainmentCheck(destination, c) and
    hasContentMagicCheck(c)
  )
}

module UploadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isUploadSource(source) }

  predicate isSink(DataFlow::Node sink) {
    exists(Expr e |
      sink.asExpr() = e and
      isDiskWriteSinkExpr(e) and
      not hasStrongUploadControls(e)
    )
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UploadFlow = TaintTracking::Global<UploadConfig>;

from UploadFlow::PathNode source, UploadFlow::PathNode sink
where UploadFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Uploaded data reaches this file write without strong file type, file name, and destination controls."
