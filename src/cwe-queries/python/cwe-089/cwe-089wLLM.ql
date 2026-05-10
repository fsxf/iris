/**
 * @name Python SQL injection with LLM-labelled sources and sinks
 * @description Tracks LLM-labelled untrusted input into SQL execution APIs.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision medium
 * @id py/iris-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import MySqlInjectionQuery
import MySqlInjectionFlow::PathGraph

from MySqlInjectionFlow::PathNode source, MySqlInjectionFlow::PathNode sink
where MySqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "SQL query built using a $@.", source.getNode(),
  "LLM-labelled user-provided value"
