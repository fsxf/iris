/**
 * @name Unrestricted file upload to disk
 * @description Uploaded content or uploaded file names are written to disk without strong file type, file name, and destination controls.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 8.1
 * @precision medium
 * @id py/unrestricted-file-upload
 * @tags security
 *       external/cwe/cwe-434
 */

import python
private import semmle.python.ApiGraphs
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
import UploadFlow::PathGraph

API::Node flaskRequestFile() {
  result = API::moduleImport("flask").getMember("request").getMember("files").getASubscript()
  or
  result = API::moduleImport("flask").getMember("request").getMember("files").getMember("get").getReturn()
  or
  result =
    API::moduleImport("flask")
        .getMember("request")
        .getMember("files")
        .getMember("getlist")
        .getReturn()
        .getASubscript()
}

API::Node djangoRequestFile() {
  result = API::moduleImport("django").getMember("http").getMember("HttpRequest").getReturn().getMember("FILES").getASubscript()
  or
  result = API::moduleImport("django").getMember("http").getMember("request").getMember("FILES").getASubscript()
}

API::Node uploadFileType() {
  result = API::moduleImport("fastapi").getMember("UploadFile")
  or
  result = API::moduleImport("starlette").getMember("datastructures").getMember("UploadFile")
}

predicate isUploadFileParameter(DataFlow::ParameterNode parameter) {
  parameter.getParameter().getAnnotation() = uploadFileType().getAValueReachableFromSource().asExpr()
}

predicate isUploadSource(DataFlow::Node source) {
  source = flaskRequestFile().asSource()
  or
  source = flaskRequestFile().getMember(["filename", "content_type", "stream"]).asSource()
  or
  source = flaskRequestFile().getMember(["read", "save"]).getReturn().asSource()
  or
  source = djangoRequestFile().asSource()
  or
  source = djangoRequestFile().getMember(["name", "content_type", "chunks", "read"]).getReturn().asSource()
  or
  exists(DataFlow::ParameterNode parameter |
    source = parameter and
    isUploadFileParameter(parameter)
  )
  or
  exists(DataFlow::AttrRead attr, DataFlow::ParameterNode parameter |
    source = attr and
    attr.accesses(parameter, ["filename", "content_type", "file"]) and
    isUploadFileParameter(parameter)
  )
  or
  exists(DataFlow::MethodCallNode call, DataFlow::ParameterNode parameter |
    source = call and
    call.calls(parameter, ["read", "seek"]) and
    isUploadFileParameter(parameter)
  )
  or
  exists(DataFlow::AttrRead attr |
    source = attr and
    attr.getAttributeName() in ["filename", "content_type", "file"] and
    attr.getObject().toString().regexpMatch("(?i).*upload.*|.*file.*")
  )
}

predicate isDiskWriteSink(DataFlow::Node sink) {
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() = "save" and
    (
      sink = call.getObject()
      or
      sink in [call.getArg(0), call.getArgByName("dst")]
    )
  )
  or
  exists(DataFlow::MethodCallNode call |
    call.getMethodName() in ["write", "write_bytes", "open"] and
    (
      sink = call.getArg(0)
      or
      call.getMethodName() = "write_bytes" and sink = call.getObject()
      or
      call.getMethodName() = "open" and sink = call.getObject()
    )
  )
  or
  sink = API::builtin("open").getACall().getArg(0)
  or
  sink = API::moduleImport("os").getMember("open").getACall().getArg(0)
  or
  sink = API::moduleImport("shutil").getMember("copyfileobj").getACall().getArg(0)
}

predicate hasServerControlledFileName(Scope scope) {
  exists(DataFlow::CallCfgNode call |
    call.getScope() = scope and
    (
      call = API::moduleImport("uuid").getMember("uuid4").getACall()
      or
      call = API::moduleImport("tempfile").getMember(["NamedTemporaryFile", "mkstemp"]).getACall()
    )
  )
}

predicate hasDestinationContainmentCheck(Scope scope) {
  exists(DataFlow::MethodCallNode call |
    call.getScope() = scope and
    call.getMethodName() in ["relative_to", "resolve"]
  )
  or
  exists(DataFlow::CallCfgNode call |
    call.getScope() = scope and
    (
      call = API::moduleImport("os").getMember("path").getMember(["commonpath", "realpath"]).getACall()
      or
      call = API::moduleImport("pathlib").getMember("Path").getMember("resolve").getACall()
    )
  )
}

predicate hasContentMagicCheck(Scope scope) {
  exists(DataFlow::MethodCallNode call |
    call.getScope() = scope and
    call.getMethodName() in ["read", "peek"]
  ) and
  exists(Bytes bytes |
    bytes.getScope() = scope and
    bytes.getText().length() > 0
  )
}

predicate hasStrongUploadControls(DataFlow::Node sink) {
  hasServerControlledFileName(sink.getScope()) and
  hasDestinationContainmentCheck(sink.getScope()) and
  hasContentMagicCheck(sink.getScope())
}

module UploadConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isUploadSource(source) }

  predicate isSink(DataFlow::Node sink) {
    isDiskWriteSink(sink) and
    not hasStrongUploadControls(sink)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module UploadFlow = TaintTracking::Global<UploadConfig>;

from UploadFlow::PathNode source, UploadFlow::PathNode sink
where UploadFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Uploaded data reaches this file write without strong file type, file name, and destination controls."
