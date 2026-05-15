/**
 * @name Python deserialization of untrusted data with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted input into deserialization APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision medium
 * @id py/iris-unsafe-deserialization
 * @tags security
 *       external/cwe/cwe-502
 */

import python
import MyUnsafeDeserializationQuery
import MyUnsafeDeserializationFlow::PathGraph

from MyUnsafeDeserializationFlow::PathNode source, MyUnsafeDeserializationFlow::PathNode sink
where MyUnsafeDeserializationFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe deserialization depends on a $@.",
  source.getNode(), "LLM-labelled user-provided value"
