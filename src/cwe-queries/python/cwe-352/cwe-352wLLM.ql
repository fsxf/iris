/**
 * @name Python JSONP injection with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted callback data into JSONP-style browser responses.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.5
 * @precision medium
 * @id py/iris-jsonp-injection
 * @tags security
 *       external/cwe/cwe-352
 */

import python
import MyJsonpInjectionQuery
import MyJsonpInjectionFlow::PathGraph

from MyJsonpInjectionFlow::PathNode source, MyJsonpInjectionFlow::PathNode sink
where MyJsonpInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "JSONP response might include code from a $@.",
  source.getNode(), "LLM-labelled user-provided callback value"
