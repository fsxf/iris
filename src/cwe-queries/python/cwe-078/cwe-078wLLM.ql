/**
 * @name Python command injection with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted input into LLM-labelled command execution APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id py/iris-command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import python
import MyCommandInjectionQuery
import MyCommandInjectionFlow::PathGraph

from MyCommandInjectionFlow::PathNode source, MyCommandInjectionFlow::PathNode sink
where MyCommandInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This command line depends on a $@.", source.getNode(),
  "LLM-labelled user-provided value"
