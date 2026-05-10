/**
 * @name C/C++ server-side request forgery with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted input into outbound request APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id cpp/iris-ssrf
 * @tags security
 *       external/cwe/cwe-918
 */

import cpp
import MyRequestForgeryQuery
import MyRequestForgeryFlow::PathGraph

from MyRequestForgeryFlow::PathNode source, MyRequestForgeryFlow::PathNode sink
where MyRequestForgeryFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential server-side request forgery due to a $@.",
  source.getNode(), "LLM-labelled user-provided value"
