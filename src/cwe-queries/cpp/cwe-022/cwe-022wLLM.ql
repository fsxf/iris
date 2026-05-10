/**
 * @name C/C++ path traversal with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted path input into LLM-labelled filesystem APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id cpp/iris-path-injection
 * @tags security
 *       external/cwe/cwe-022
 */

import cpp
import MyTaintedPathQuery
import MyTaintedPathFlow::PathGraph

from MyTaintedPathFlow::PathNode source, MyTaintedPathFlow::PathNode sink
where MyTaintedPathFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "This path depends on a $@.", source.getNode(),
  "LLM-labelled user-provided value"
