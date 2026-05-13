/**
 * @name Divide by zero
 * @description Division or remainder by a value that can be zero.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id java/divide-by-zero
 * @tags security
 *       external/cwe/cwe-369
 */

import java
import Cwe369ValueFlow
import MayZeroFlow::PathGraph

from MayZeroFlow::PathNode source, MayZeroFlow::PathNode sink, DivisionOrRemainder div
where
  MayZeroFlow::flowPath(source, sink) and
  sink.getNode().asExpr() = div.getDenominator() and
  not protectedDenominator(div)
select div, source, sink,
  "A value that may be zero reaches this denominator without a non-zero guard."
