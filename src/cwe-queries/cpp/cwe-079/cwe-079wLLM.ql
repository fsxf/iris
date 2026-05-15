/**
 * @name C/C++ cross-site scripting with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted input into HTML or script output APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id cpp/iris-xss
 * @tags security
 *       external/cwe/cwe-079
 */

import cpp
import MyXssQuery
import MyXssFlow::PathGraph

from MyXssFlow::PathNode source, MyXssFlow::PathNode sink
where MyXssFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Potential cross-site scripting due to a $@.",
  source.getNode(), "LLM-labelled user-provided value"
