/**
 * @name Cleartext transmission of sensitive information over HTTP
 * @description Sensitive data sent to a cleartext HTTP endpoint may be intercepted in transit.
 * @kind path-problem
 * @id py/custom/cleartext-sensitive-http
 * @problem.severity warning
 * @security-severity 8.2
 * @precision medium
 * @tags security
 *       external/cwe/cwe-319
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.CleartextStorageCustomizations

private predicate looksLikeCleartextHttp(API::Node node) {
  exists(DataFlow::Node value |
    value = node.getAValueReachingSink() and
    value.asExpr().(StringLiteral).getText().regexpMatch("(?i)^http://.*")
  )
}

private predicate isRequestsWrapper(string method) {
  method = "get" or
  method = "post" or
  method = "put" or
  method = "patch" or
  method = "delete" or
  method = "head" or
  method = "options"
}

private predicate cleartextRequestsWrapperSink(DataFlow::Node sink) {
  exists(string method, API::CallNode call |
    isRequestsWrapper(method) and
    (
      call = API::moduleImport("requests").getMember(method).getACall()
      or
      call =
        API::moduleImport("requests").getMember("Session").getReturn().getMember(method).getACall()
    ) and
    looksLikeCleartextHttp(call.getParameter(0, "url")) and
    sink =
      [
        call.getParameter(0, "url").asSink(),
        call.getParameter(1, "params").asSink(),
        call.getParameter(1, "data").asSink(),
        call.getParameter(1, "json").asSink(),
        call.getParameter(2, "headers").asSink(),
        call.getParameter(2, "cookies").asSink(),
        call.getParameter(2, "auth").asSink(),
        call.getParameter(2, "files").asSink()
      ]
  )
}

private predicate cleartextRequestsRequestSink(DataFlow::Node sink) {
  exists(API::CallNode call |
    (
      call = API::moduleImport("requests").getMember("request").getACall()
      or
      call =
        API::moduleImport("requests").getMember("Session").getReturn().getMember("request").getACall()
    ) and
    looksLikeCleartextHttp(call.getParameter(1, "url")) and
    sink =
      [
        call.getParameter(1, "url").asSink(),
        call.getParameter(2, "params").asSink(),
        call.getParameter(2, "data").asSink(),
        call.getParameter(2, "json").asSink(),
        call.getParameter(3, "headers").asSink(),
        call.getParameter(3, "cookies").asSink(),
        call.getParameter(3, "auth").asSink(),
        call.getParameter(3, "files").asSink()
      ]
  )
}

private predicate cleartextUrllibSink(DataFlow::Node sink) {
  exists(API::CallNode call |
    call = API::moduleImport("urllib.request").getMember("urlopen").getACall() and
    looksLikeCleartextHttp(call.getParameter(0, "url")) and
    sink = [call.getParameter(0, "url").asSink(), call.getParameter(1, "data").asSink()]
  )
  or
  exists(API::CallNode call |
    call = API::moduleImport("urllib.request").getMember("Request").getACall() and
    looksLikeCleartextHttp(call.getParameter(0, "url")) and
    sink =
      [call.getParameter(0, "url").asSink(), call.getParameter(1, "data").asSink(),
        call.getParameter(2, "headers").asSink()]
  )
}

private predicate cleartextHttpClientSink(DataFlow::Node sink) {
  exists(API::CallNode call |
    call =
      API::moduleImport("http.client").getMember("HTTPConnection").getReturn().getMember("request")
          .getACall() and
    (
      sink = call.getParameter(1, "url").asSink() or
      sink = call.getParameter(2, "body").asSink() or
      sink = call.getParameter(3, "headers").asSink()
    )
  )
}

private class CleartextTransmissionSink extends DataFlow::Node {
  CleartextTransmissionSink() {
    cleartextRequestsWrapperSink(this) or
    cleartextRequestsRequestSink(this) or
    cleartextUrllibSink(this) or
    cleartextHttpClientSink(this)
  }
}

module SensitiveToCleartextHttpConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CleartextStorage::Source
  }

  predicate isSink(DataFlow::Node sink) {
    sink instanceof CleartextTransmissionSink
  }
}

module SensitiveToCleartextHttpFlow = TaintTracking::Global<SensitiveToCleartextHttpConfig>;

import SensitiveToCleartextHttpFlow::PathGraph

from SensitiveToCleartextHttpFlow::PathNode source, SensitiveToCleartextHttpFlow::PathNode sink
where SensitiveToCleartextHttpFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Sensitive data may be transmitted over cleartext HTTP here."
