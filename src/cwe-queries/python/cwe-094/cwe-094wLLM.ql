/**
 * @name Python code injection with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted input into dynamic code evaluation APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision medium
 * @id py/iris-code-injection
 * @tags security
 *       external/cwe/cwe-094
 */

import python
import MyCodeInjectionQuery
import MyCodeInjectionFlow::PathGraph

from MyCodeInjectionFlow::PathNode source, MyCodeInjectionFlow::PathNode sink
where MyCodeInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Dynamically evaluated code depends on a $@.",
  source.getNode(), "LLM-labelled user-provided value"
