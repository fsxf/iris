/**
 * @name Python XML external entity expansion with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted XML input into XML parser APIs that may resolve external entities.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.1
 * @precision medium
 * @id py/iris-xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import python
import MyXxeQuery
import MyXxeFlow::PathGraph

from MyXxeFlow::PathNode source, MyXxeFlow::PathNode sink
where MyXxeFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "XML parsing depends on a $@ without guarding against external entity expansion.",
  source.getNode(), "LLM-labelled user-provided value"
